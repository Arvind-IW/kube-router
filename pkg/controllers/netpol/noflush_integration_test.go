//go:build linux

// Integration test for the --noflush restore redesign (upstream #1372).
// Requires a privileged Linux environment with real iptables (e.g. Docker
// --privileged). Proves that NPC's restore leaves foreign (GEHC) chains alone
// across repeated sync cycles.

package netpol

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1core "k8s.io/api/core/v1"
)

func mustRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %s", name, args, out)
	}
	return string(out)
}

// seedGehc simulates GEHC's host-managed firewall: a custom chain jumped from
// INPUT with the modality API ACCEPT and metrics DROP rules.
func seedGehc(t *testing.T) {
	mustRun(t, "iptables", "-N", "GEHC-HOST-FW")
	mustRun(t, "iptables", "-A", "GEHC-HOST-FW", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
	mustRun(t, "iptables", "-A", "GEHC-HOST-FW", "-p", "tcp", "--dport", "9100", "-j", "DROP")
	mustRun(t, "iptables", "-A", "INPUT", "-j", "GEHC-HOST-FW")
}

// gehcSurvived reports whether GEHC's host chain and its modality API rule are
// still present, read via iptables-save (reliable across the nft and legacy
// backends, and the same check the reproduction in the goal specifies).
func gehcSurvived(t *testing.T) bool {
	out := mustRun(t, "iptables-save")
	return bytes.Contains([]byte(out), []byte("-A GEHC-HOST-FW")) &&
		bytes.Contains([]byte(out), []byte("--dport 8443"))
}

func TestNoflushPreservesForeignChains(t *testing.T) {
	// Reset the filter table to a clean slate first
	mustRun(t, "iptables", "-F")
	mustRun(t, "iptables", "-X")
	seedGehc(t)
	if !gehcSurvived(t) {
		t.Fatal("seed GEHC chains missing")
	}

	restore := utils.NewIPTablesSaveRestore(v1core.IPv4Protocol)
	for i := 0; i < 20; i++ {
		// Build the restore input the way NPC's sync does: snapshot the table,
		// then keep ONLY kube-router-owned chains (foreign chains dropped from
		// the input so --noflush leaves them alone).
		var buf bytes.Buffer
		if err := restore.SaveInto("filter", &buf); err != nil {
			t.Fatalf("SaveInto: %v", err)
		}
		desired := filterToManagedChains(&buf)
		// include a kube-router chain so NPC's "own" content is present each cycle
		if i == 0 {
			mustRun(t, "iptables", "-N", "KUBE-ROUTER-INPUT")
		}
		if err := restore.Restore("filter", desired.Bytes()); err != nil {
			t.Fatalf("Restore cycle %d: %v", i, err)
		}
		if !gehcSurvived(t) {
			t.Fatalf("GEHC-HOST-FW wiped at cycle %d", i)
		}
	}
	if !gehcSurvived(t) {
		t.Fatal("GEHC-HOST-FW permanently lost")
	}
}

// filterToManagedChains keeps only NPC-owned chain defs/rules from a full
// iptables-save buffer, mirroring the fix's cleanupStaleRules behavior.
func filterToManagedChains(src *bytes.Buffer) *bytes.Buffer {
	out := &bytes.Buffer{}
	out.WriteString("*filter\n")
	for _, rule := range bytes.Split(src.Bytes(), []byte("\n")) {
		var chain string
		switch {
		case bytes.HasPrefix(rule, []byte(":")):
			chain = string(bytes.Fields(rule[1:])[0])
		case bytes.HasPrefix(rule, []byte("-A")), bytes.HasPrefix(rule, []byte("-I")):
			f := bytes.Fields(rule)
			if len(f) > 1 {
				chain = string(f[1])
			}
		}
		if chain == "" || !isKubeRouterManagedChain(chain) {
			continue
		}
		if bytes.HasPrefix(rule, []byte(":")) {
			out.Write(append(rule, []byte(" - [0:0]\n")...))
		} else {
			out.Write(append(rule, '\n'))
		}
	}
	out.WriteString("COMMIT\n")
	return out
}

// TestFlushModeWipesForeignChainsBaseline demonstrates the pre-fix bug: a
// restore in iptables-restore's default (flushing) mode, with only NPC chains in
// the input, wipes the foreign GEHC chain. This is the behavior the --noflush
// fix removes; it proves the passing test above is meaningful.
func TestFlushModeWipesForeignChainsBaseline(t *testing.T) {
	mustRun(t, "iptables", "-F")
	mustRun(t, "iptables", "-X")
	seedGehc(t)
	if !gehcSurvived(t) {
		t.Fatal("seed GEHC chains missing")
	}
	// Same input the fixed code builds (NPC chains only, foreign chains filtered
	// out), but restored WITHOUT --noflush == the old flushing behavior.
	var buf bytes.Buffer
	if err := utils.NewIPTablesSaveRestore(v1core.IPv4Protocol).SaveInto("filter", &buf); err != nil {
		t.Fatalf("SaveInto: %v", err)
	}
	desired := filterToManagedChains(&buf)
	cmd := exec.Command("iptables-restore", "-T", "filter")
	cmd.Stdin = desired
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("flush restore: %v: %s", err, out)
	}
	if gehcSurvived(t) {
		t.Fatal("expected GEHC-HOST-FW to be wiped by flush-mode restore, but it survived")
	}
}

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("iptables"); err != nil {
		os.Exit(0) // skip silently when iptables isn't available
	}
	os.Exit(m.Run())
}
