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
	"github.com/coreos/go-iptables/iptables"
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
	// Create an NPC-owned chain so each cycle's input actually carries NPC
	// content alongside the foreign chains that must be left alone.
	mustRun(t, "iptables", "-N", "KUBE-ROUTER-INPUT")
	mustRun(t, "iptables", "-A", "KUBE-ROUTER-INPUT", "-j", "RETURN")
	for i := range 20 {
		// Build the restore input the way NPC's sync does: snapshot the table,
		// then keep ONLY kube-router-owned chains (foreign chains dropped from
		// the input so --noflush leaves them alone).
		var buf bytes.Buffer
		if err := restore.SaveInto("filter", &buf); err != nil {
			t.Fatalf("SaveInto: %v", err)
		}
		desired := bytes.NewBuffer(buildNoflushRestoreInput(buf.String(), nil, nil))
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
	// NPC's own chain must still be managed (and thus present) after the cycles.
	if !bytes.Contains([]byte(mustRun(t, "iptables-save")), []byte(":KUBE-ROUTER-INPUT")) {
		t.Error("kube-router's own chain was lost across cycles")
	}
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
	desired := bytes.NewBuffer(buildNoflushRestoreInput(buf.String(), nil, nil))
	cmd := exec.Command("iptables-restore", "-T", "filter")
	cmd.Stdin = desired
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("flush restore: %v: %s", err, out)
	}
	if gehcSurvived(t) {
		t.Fatal("expected GEHC-HOST-FW to be wiped by flush-mode restore, but it survived")
	}
}

// TestCleanupRemovesOnlyKubeRouterChains proves the Cleanup() path: NPC must be
// able to remove itself entirely under --noflush (where omission from the
// restore input no longer deletes anything) without touching foreign chains.
func TestCleanupRemovesOnlyKubeRouterChains(t *testing.T) {
	mustRun(t, "iptables", "-F")
	mustRun(t, "iptables", "-X")
	seedGehc(t)

	npcChains := []string{
		"KUBE-ROUTER-INPUT", "KUBE-ROUTER-FORWARD", "KUBE-ROUTER-OUTPUT",
		"KUBE-NWPLCY-DEFAULT", "KUBE-NWPLCY-COMMON", "KUBE-POD-FW-abc123",
	}
	for _, c := range npcChains {
		mustRun(t, "iptables", "-N", c)
	}
	// NPC's own rules in the shared builtin chains.
	mustRun(t, "iptables", "-A", "INPUT", "-m", "comment", "--comment", "kube-router netpol - ABCDEF",
		"-j", "KUBE-ROUTER-INPUT")
	mustRun(t, "iptables", "-A", "FORWARD", "-m", "comment", "--comment", "kube-router netpol - GHIJKL",
		"-j", "KUBE-ROUTER-FORWARD")
	mustRun(t, "iptables", "-A", "OUTPUT", "-m", "comment", "--comment", "kube-router netpol - MNOPQR",
		"-j", "KUBE-ROUTER-OUTPUT")
	mustRun(t, "iptables", "-A", "FORWARD", "-m", "comment", "--comment",
		"KUBE-ROUTER rule to explicitly ACCEPT traffic that comply to network policies",
		"-m", "mark", "--mark", "0x20000/0x20000", "-j", "ACCEPT")
	// A foreign rule in a builtin chain that must be left alone.
	mustRun(t, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "9999", "-j", "ACCEPT")
	// Cross-references between NPC chains: these keep the chains from being
	// deletable until they are flushed first.
	mustRun(t, "iptables", "-A", "KUBE-NWPLCY-DEFAULT", "-j", "KUBE-NWPLCY-COMMON")
	mustRun(t, "iptables", "-A", "KUBE-ROUTER-FORWARD", "-j", "KUBE-POD-FW-abc123")

	handler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		t.Fatalf("iptables handler: %v", err)
	}
	npc := &NetworkPolicyController{
		iptablesCmdHandlers: map[v1core.IPFamily]utils.IPTablesHandler{v1core.IPv4Protocol: handler},
	}
	npc.deleteKubeRouterFilterChains()

	save := mustRun(t, "iptables-save")
	for _, c := range npcChains {
		if bytes.Contains([]byte(save), []byte(":"+c+" ")) {
			t.Errorf("kube-router chain %s survived cleanup", c)
		}
	}
	if bytes.Contains([]byte(save), []byte("kube-router netpol")) ||
		bytes.Contains([]byte(save), []byte("explicitly ACCEPT traffic")) {
		t.Error("kube-router rules survived in the builtin chains")
	}
	if !bytes.Contains([]byte(save), []byte("--dport 9999")) {
		t.Error("foreign rule in INPUT was removed by cleanup")
	}
	if !gehcSurvived(t) {
		t.Error("foreign GEHC chain was removed by cleanup")
	}
}

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("iptables"); err != nil {
		os.Exit(0) // skip silently when iptables isn't available
	}
	os.Exit(m.Run())
}
