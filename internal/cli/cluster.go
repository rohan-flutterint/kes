package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cluster"
	"github.com/minio/kes/internal/sys"
	"golang.org/x/term"
)

func PrintStartupMessage(node *cluster.Node) {
	var faint, item tui.Style
	if term.IsTerminal(int(os.Stdout.Fd())) {
		faint = faint.Faint(true)
		item = item.Foreground(tui.Color("#2e42d1")).Bold(true)
	}

	var self cluster.NodeID
	members, config := node.MemberSet(), node.Config()
	ids := make([]cluster.NodeID, 0, len(members))
	for id, addr := range members {
		ids = append(ids, id)
		if addr == config.Addr {
			self = id
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	buffer := new(Buffer)
	buffer.Stylef(item, "%-12s", "Copyright").Sprintf("%-22s", "MinIO, Inc.").Styleln(faint, "https://min.io")
	buffer.Stylef(item, "%-12s", "License").Sprintf("%-22s", "GNU AGPLv3").Styleln(faint, "https://www.gnu.org/licenses/agpl-3.0.html")
	buffer.Stylef(item, "%-12s", "Version").Sprintf("%-22s", sys.BinaryInfo().Version).Stylef(faint, "%s/%s\n", runtime.GOOS, runtime.GOARCH)
	buffer.Sprintln()

	buffer.Stylef(item, "%-12s", "Cluster").Styleln(faint, "Node   Address")
	for _, id := range ids {
		buffer.Sprintf("%-12s%-6s %s", " ", "["+strconv.Itoa(int(id))+"]", members[id])
		if id == self {
			buffer.Stylef(item, "  ●")
		}
		buffer.Sprintln()
	}
	buffer.Sprintln()

	buffer.Stylef(item, "%-12s", "Admin")
	if r, err := hex.DecodeString(config.Admin.String()); err == nil && len(r) == sha256.Size {
		buffer.Sprintln(config.Admin)
	} else {
		buffer.Sprintf("%-22s", "_").Styleln(faint, "[ disabled ]")
	}
	if config.Admin == config.APIKey.Identity() {
		buffer.Stylef(item, "%-12s", "API Key").Sprintln(config.APIKey.String())
	}
	buffer.Sprintln()

	buffer.Stylef(item, "%-12s", "Docs").Sprintln("<link-to-docs>")
	buffer.Stylef(item, "%-12s", "CLI Access").Sprintf("$ export KES_SERVER=https://%s", config.Addr).Sprintln()
	if config.Admin == config.APIKey.Identity() {
		buffer.Sprintf("%-12s$ export KES_API_KEY=%s", " ", config.APIKey.String()).Sprintln()
	}
	buffer.Sprintf("%-12s$ kes --help", " ")

	fmt.Println(buffer.String())
}
