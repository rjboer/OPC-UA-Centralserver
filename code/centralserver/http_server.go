package centralserver

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const healthStaleAfter = 10 * time.Second

type healthResponse struct {
	Status        string            `json:"status"`
	Service       string            `json:"service"`
	TimeUTC       string            `json:"time_utc"`
	UptimeSeconds int64             `json:"uptime_seconds"`
	Endpoints     map[string]string `json:"endpoints"`
	Checks        map[string]bool   `json:"checks"`
	Runtime       map[string]any    `json:"runtime"`
	Error         string            `json:"error,omitempty"`
}

type adminPageData struct {
	Health    healthResponse
	Modules   []ModuleStatusView
	Flash     string
	ModuleMap []moduleTypeOption
}

type moduleTypeOption struct {
	Value int
	Label string
}

var adminPageTemplate = template.Must(template.New("admin").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OPC UA Centralserver Admin</title>
  <style>
    :root {
      --bg: #f5f1e8;
      --panel: #fffaf2;
      --ink: #1f2a30;
      --muted: #66757d;
      --accent: #0f766e;
      --warn: #b45309;
      --line: #d8cbb4;
    }
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #efe6d6 0%, var(--bg) 100%);
      color: var(--ink);
    }
    main {
      max-width: 1120px;
      margin: 0 auto;
      padding: 24px;
    }
    h1, h2 { margin: 0 0 12px; }
    p { color: var(--muted); }
    .grid {
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 10px 30px rgba(31, 42, 48, 0.08);
    }
    .flash {
      margin-bottom: 18px;
      padding: 12px 14px;
      border-radius: 12px;
      background: #ecfccb;
      border: 1px solid #bef264;
      color: #365314;
    }
    .status-ok { color: var(--accent); }
    .status-degraded { color: var(--warn); }
    form {
      display: grid;
      gap: 10px;
    }
    label {
      display: grid;
      gap: 6px;
      font-size: 14px;
      color: var(--muted);
    }
    input, select, button {
      font: inherit;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: white;
      color: var(--ink);
    }
    button {
      cursor: pointer;
      background: var(--ink);
      color: white;
      border: none;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: middle;
    }
    .row-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      background: #e2e8f0;
      font-size: 12px;
    }
    .badge.active {
      background: #ccfbf1;
      color: #115e59;
    }
    .badge.inactive {
      background: #fef3c7;
      color: #92400e;
    }
    @media (max-width: 720px) {
      table, thead, tbody, th, td, tr { display: block; }
      thead { display: none; }
      td { padding: 8px 0; border-bottom: none; }
      tr {
        padding: 12px 0;
        border-bottom: 1px solid var(--line);
      }
    }
  </style>
</head>
<body>
  <main>
    <h1>Centralserver Admin</h1>
    <p>One shared memory, two OPC UA projections, one operator interface.</p>
    {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}

    <div class="grid">
      <section class="card">
        <h2>Health</h2>
        <p>Status: <strong class="status-{{.Health.Status}}">{{.Health.Status}}</strong></p>
        <p>Last publish: {{index .Health.Runtime "last_publish_utc"}}</p>
        <p>General OPC UA: {{index .Health.Endpoints "opcua_general"}}</p>
        <p>SCADA OPC UA: {{index .Health.Endpoints "opcua_scada"}}</p>
      </section>

      <section class="card">
        <h2>Add Module</h2>
        <form method="post" action="/admin/modules">
          <label>Serial number
            <input type="number" name="serial_number" min="1" required>
          </label>
          <label>Module type
            <select name="module_type">
              {{range .ModuleMap}}<option value="{{.Value}}">{{.Label}}</option>{{end}}
            </select>
          </label>
          <label>Vendor ID
            <input type="number" name="vendor_id" min="1" value="1" required>
          </label>
          <button type="submit">Add Or Activate Module</button>
        </form>
      </section>
    </div>

    <section class="card" style="margin-top: 18px;">
      <h2>Modules In Memory</h2>
      <table>
        <thead>
          <tr>
            <th>Kind</th>
            <th>Index</th>
            <th>Serial</th>
            <th>Module Type</th>
            <th>Vendor</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {{range .Modules}}
          <tr>
            <td>{{.Kind}}</td>
            <td>{{.Index}}</td>
            <td>{{.SerialNumber}}</td>
            <td>{{.ModuleType}}</td>
            <td>{{.VendorID}}</td>
            <td>{{if .Active}}<span class="badge active">active</span>{{else}}<span class="badge inactive">inactive</span>{{end}}</td>
            <td>
              <div class="row-actions">
                <form method="post" action="/admin/modules/activate">
                  <input type="hidden" name="serial_number" value="{{.SerialNumber}}">
                  <input type="hidden" name="module_type" value="{{.ModuleType}}">
                  <input type="hidden" name="vendor_id" value="{{.VendorID}}">
                  <button type="submit">Activate</button>
                </form>
                <form method="post" action="/admin/modules/deactivate">
                  <input type="hidden" name="serial_number" value="{{.SerialNumber}}">
                  <input type="hidden" name="module_type" value="{{.ModuleType}}">
                  <input type="hidden" name="vendor_id" value="{{.VendorID}}">
                  <button type="submit">Deactivate</button>
                </form>
              </div>
            </td>
          </tr>
          {{else}}
          <tr><td colspan="7">No modules have been added to memory yet.</td></tr>
          {{end}}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>`))

func (p *Process) startHTTPServer() error {
	if p.Config.HTTPPort == 0 {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleIndex)
	mux.HandleFunc("/health", p.handleHealth)
	mux.HandleFunc("/healthz", p.handleHealth)
	mux.HandleFunc("/admin", p.handleAdmin)
	mux.HandleFunc("/admin/modules", p.handleAddModule)
	mux.HandleFunc("/admin/modules/activate", p.handleActivateModule)
	mux.HandleFunc("/admin/modules/deactivate", p.handleDeactivateModule)
	mux.HandleFunc("/api/modules", p.handleModulesAPI)

	p.httpServer = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", p.Config.Host, p.Config.HTTPPort),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.recordPublishResult(err)
		}
	}()

	return nil
}

func (p *Process) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	resp := map[string]string{
		"service": "opc-ua-centralserver",
		"health":  "/health",
		"healthz": "/healthz",
		"admin":   "/admin",
		"modules": "/api/modules",
	}
	writeJSON(w, http.StatusOK, resp)
}

func (p *Process) handleHealth(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()

	p.statusMu.RLock()
	startedAt := p.startedAt
	lastPublish := p.lastPublish
	lastError := p.lastError
	p.statusMu.RUnlock()

	checks := map[string]bool{
		"general_server_running": p.General != nil && p.General.Server != nil,
		"scada_server_running":   p.SCADA != nil && p.SCADA.Server != nil,
		"snapshot_published":     !lastPublish.IsZero(),
		"snapshot_fresh":         !lastPublish.IsZero() && now.Sub(lastPublish) <= healthStaleAfter,
	}

	statusCode := http.StatusOK
	status := "ok"
	if !checks["general_server_running"] || !checks["scada_server_running"] || !checks["snapshot_fresh"] || lastError != "" {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, statusCode, healthResponse{
		Status:        status,
		Service:       "opc-ua-centralserver",
		TimeUTC:       now.Format(time.RFC3339),
		UptimeSeconds: int64(now.Sub(startedAt).Seconds()),
		Endpoints: map[string]string{
			"http":          fmt.Sprintf("http://%s:%d", p.Config.Host, p.Config.HTTPPort),
			"opcua_general": fmt.Sprintf("opc.tcp://%s:%d", p.Config.Host, p.Config.GeneralPort),
			"opcua_scada":   fmt.Sprintf("opc.tcp://%s:%d", p.Config.Host, p.Config.SCADAPort),
		},
		Checks: checks,
		Runtime: map[string]any{
			"demo_mode":                p.Config.DemoMode,
			"memory_model":             "System",
			"publish_interval_seconds": 2,
			"last_publish_utc":         formatTime(lastPublish),
		},
		Error: lastError,
	})
}

func (p *Process) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()

	p.statusMu.RLock()
	startedAt := p.startedAt
	lastPublish := p.lastPublish
	lastError := p.lastError
	p.statusMu.RUnlock()

	checks := map[string]bool{
		"general_server_running": p.General != nil && p.General.Server != nil,
		"scada_server_running":   p.SCADA != nil && p.SCADA.Server != nil,
		"snapshot_published":     !lastPublish.IsZero(),
		"snapshot_fresh":         !lastPublish.IsZero() && now.Sub(lastPublish) <= healthStaleAfter,
	}

	status := "ok"
	if !checks["general_server_running"] || !checks["scada_server_running"] || !checks["snapshot_fresh"] || lastError != "" {
		status = "degraded"
	}

	data := adminPageData{
		Health: healthResponse{
			Status:        status,
			Service:       "opc-ua-centralserver",
			TimeUTC:       now.Format(time.RFC3339),
			UptimeSeconds: int64(now.Sub(startedAt).Seconds()),
			Endpoints: map[string]string{
				"http":          fmt.Sprintf("http://%s:%d", p.Config.Host, p.Config.HTTPPort),
				"opcua_general": fmt.Sprintf("opc.tcp://%s:%d", p.Config.Host, p.Config.GeneralPort),
				"opcua_scada":   fmt.Sprintf("opc.tcp://%s:%d", p.Config.Host, p.Config.SCADAPort),
			},
			Checks: checks,
			Runtime: map[string]any{
				"demo_mode":                p.Config.DemoMode,
				"memory_model":             "System",
				"publish_interval_seconds": 2,
				"last_publish_utc":         formatTime(lastPublish),
			},
			Error: lastError,
		},
		Modules:   p.Memory.ListModules(),
		Flash:     r.URL.Query().Get("flash"),
		ModuleMap: moduleTypeOptions(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminPageTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Process) handleAddModule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identity, err := parseIdentityForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	enrollment, err := p.Memory.AddModule(identity)
	if err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	p.Memory.RecordBackupEnrollment(identity, enrollment, true, "WebAddModule")
	if err := p.refreshPublishedState(); err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?flash=module+added+or+activated", http.StatusSeeOther)
}

func (p *Process) handleActivateModule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identity, err := parseIdentityForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	if _, err := p.Memory.SetModuleActive(identity, true); err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := p.refreshPublishedState(); err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?flash=module+activated", http.StatusSeeOther)
}

func (p *Process) handleDeactivateModule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identity, err := parseIdentityForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	if _, err := p.Memory.SetModuleActive(identity, false); err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := p.refreshPublishedState(); err != nil {
		http.Redirect(w, r, "/admin?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?flash=module+deactivated", http.StatusSeeOther)
}

func (p *Process) handleModulesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"memory":  "System",
		"modules": p.Memory.ListModules(),
	})
}

func parseIdentityForm(r *http.Request) (IdentityType, error) {
	if err := r.ParseForm(); err != nil {
		return IdentityType{}, err
	}

	serialNumberValue, err := strconv.ParseUint(r.Form.Get("serial_number"), 10, 32)
	if err != nil {
		return IdentityType{}, fmt.Errorf("invalid serial_number")
	}
	moduleTypeValue, err := strconv.ParseUint(r.Form.Get("module_type"), 10, 8)
	if err != nil {
		return IdentityType{}, fmt.Errorf("invalid module_type")
	}
	vendorIDValue, err := strconv.ParseUint(r.Form.Get("vendor_id"), 10, 16)
	if err != nil {
		return IdentityType{}, fmt.Errorf("invalid vendor_id")
	}

	return IdentityType{
		SerialNumber: uint32(serialNumberValue),
		ModuleType:   uint8(moduleTypeValue),
		VendorID:     uint16(vendorIDValue),
	}, nil
}

func moduleTypeOptions() []moduleTypeOption {
	return []moduleTypeOption{
		{Value: int(ModuleTypeStorage), Label: "Storage (2)"},
		{Value: int(ModuleTypeCompressor), Label: "Compressor (3)"},
		{Value: int(ModuleTypeDispenserH35), Label: "Dispenser H35 (4)"},
		{Value: int(ModuleTypeDispenserH70), Label: "Dispenser H70 (5)"},
		{Value: int(ModuleTypeCoolmark), Label: "Coolmark (6)"},
		{Value: int(ModuleTypeTorus), Label: "Torus (7)"},
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}
