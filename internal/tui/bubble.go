package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/theworker02/wiretap/internal/cluster"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

type section int

const (
	secSummary section = iota
	secWarnings
	secHyps
	secObs
	secEntropy
	secClusters
	secExplain
)

var sectionNames = []string{
	"Summary", "Warnings", "Hypotheses", "Observations", "Entropy", "Clusters", "Explain@offset",
}

func runBubble(res *wt.Result, ds *wt.Dataset) error {
	var cr *cluster.Result
	if ds != nil {
		cr, _ = cluster.ClusterMessages(ds, cluster.Options{MultiSignal: true})
	}
	m := model{
		res: res, ds: ds, cr: cr,
		sec: secSummary, width: 100, height: 30,
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type model struct {
	res            *wt.Result
	ds             *wt.Dataset
	cr             *cluster.Result
	sec            section
	cursor         int
	offsetInput    string
	explainOff     int
	explainReady   bool
	width, height  int
	status         string
	enteringOffset bool
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if m.enteringOffset {
			return m.updateOffsetInput(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "right", "l":
			m.sec = (m.sec + 1) % section(len(sectionNames))
			m.cursor = 0
			m.status = ""
		case "shift+tab", "left", "h":
			m.sec--
			if m.sec < 0 {
				m.sec = section(len(sectionNames) - 1)
			}
			m.cursor = 0
			m.status = ""
		case "1", "2", "3", "4", "5", "6", "7":
			n, _ := strconv.Atoi(msg.String())
			m.sec = section(n - 1)
			m.cursor = 0
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			m.cursor++
			if max := m.maxCursor(); m.cursor > max {
				m.cursor = max
			}
		case "x":
			m.enteringOffset = true
			m.offsetInput = ""
			m.status = "explain offset: type number, Enter confirm, Esc cancel"
		case "enter":
			if m.sec == secHyps && m.cursor < len(m.res.Hypotheses) {
				h := m.res.Hypotheses[m.cursor]
				if h.Offset >= 0 {
					m.explainOff = h.Offset
					m.explainReady = true
					m.sec = secExplain
				}
			}
		case "?":
			m.status = "keys: 1-7/tab sections · ↑↓ hyps · x explain-at · q quit"
		}
	}
	return m, nil
}

func (m model) updateOffsetInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.enteringOffset = false
		m.status = ""
	case "enter":
		off, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(m.offsetInput), "0x"))
		m.enteringOffset = false
		if err != nil {
			m.status = fmt.Sprintf("bad offset: %v", err)
			return m, nil
		}
		m.explainOff = off
		m.explainReady = true
		m.sec = secExplain
		m.status = ""
	case "backspace":
		if len(m.offsetInput) > 0 {
			m.offsetInput = m.offsetInput[:len(m.offsetInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			r := msg.String()[0]
			if (r >= '0' && r <= '9') || r == 'x' {
				m.offsetInput += msg.String()
			}
		}
	}
	return m, nil
}

func (m model) maxCursor() int {
	switch m.sec {
	case secHyps:
		n := len(m.res.Hypotheses) - 1
		if n < 0 {
			return 0
		}
		if n > 200 {
			return 200
		}
		return n
	default:
		return 0
	}
}

func (m model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("36")).Render("Wiretap TUI")
	tabs := m.renderTabs()
	body := m.renderBody()
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(
		"tab/←→ sections · ↑↓ list · x explain-at-offset · 1-7 jump · q quit · NO_COLOR→plain",
	)
	status := m.status
	if m.enteringOffset {
		status = "offset> " + m.offsetInput + "▌"
	}
	parts := []string{title + "  " + tabs, "", body, "", help}
	if status != "" {
		parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(status))
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (m model) renderTabs() string {
	active := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("36")).Padding(0, 1)
	idle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	var tabs []string
	for i, name := range sectionNames {
		label := fmt.Sprintf("%d:%s", i+1, name)
		if section(i) == m.sec {
			tabs = append(tabs, active.Render(label))
		} else {
			tabs = append(tabs, idle.Render(label))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
}

func (m model) renderBody() string {
	box := lipgloss.NewStyle().Width(max(40, m.width-2)).MaxHeight(max(8, m.height-8))
	var content string
	switch m.sec {
	case secSummary:
		content = formatSummary(m.res, m.ds)
	case secWarnings:
		content = formatWarnings(m.res)
	case secHyps:
		content = m.renderHypList()
	case secObs:
		content = formatObs(m.res)
	case secEntropy:
		content = formatEntropy(m.res)
	case secClusters:
		content = formatClusters(m.cr)
	case secExplain:
		if !m.explainReady {
			content = "Press x and enter a byte offset to explain competing hypotheses.\n"
		} else {
			content = formatExplain(m.res, m.ds, m.explainOff)
		}
	}
	return box.Render(content)
}

func (m model) renderHypList() string {
	if len(m.res.Hypotheses) == 0 {
		return "(none)\n"
	}
	var b strings.Builder
	limit := 40
	start := 0
	if m.cursor >= limit {
		start = m.cursor - limit + 1
	}
	sel := lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("24"))
	for i := start; i < len(m.res.Hypotheses) && i < start+limit; i++ {
		h := m.res.Hypotheses[i]
		line := fmt.Sprintf("%s  %s off=%d len=%d conf=%s score=%.2f",
			h.ID, h.Kind, h.Offset, h.Length, h.Confidence.Level, h.Confidence.Score)
		if i == m.cursor {
			b.WriteString(sel.Render("▸ " + line))
		} else {
			b.WriteString("  " + line)
		}
		b.WriteByte('\n')
		if i == m.cursor {
			fmt.Fprintf(&b, "    %s\n", h.Description)
		}
	}
	if len(m.res.Hypotheses) > start+limit {
		fmt.Fprintf(&b, "… %d more (↓ to scroll)\n", len(m.res.Hypotheses)-(start+limit))
	}
	return b.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
