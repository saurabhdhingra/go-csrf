package templates

import (
	"html/template"
	"net/http"
	"path/filepath"
	"sync"
)

var (
	tmplOnce sync.Once
	tmpls    *template.Template
)

func loadTemplates() {
	tmpls = template.Must(template.ParseGlob(filepath.Join("templates", "*.html")))
}

// RenderTemplate renders a named template with data
func RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmplOnce.Do(loadTemplates)
	w.Header().Set("Content-Type", "text/html")
	err := tmpls.ExecuteTemplate(w, name+".html", data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}
