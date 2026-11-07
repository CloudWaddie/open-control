package control

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestFilterLifecycle(t *testing.T) {
	f := newFixture(t)

	code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator, `{"kind":"filter","ref":"ads","state":"block","level":"strict"}`)
	if code != http.StatusOK {
		t.Fatalf("enable filter: %d", code)
	}
	f.waitReload()

	// Changing the level updates the same row.
	if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator, `{"kind":"filter","ref":"ads","state":"block","level":"relaxed"}`); code != http.StatusOK {
		t.Fatalf("change level: %d", code)
	}
	f.waitReload()
	_, _, raw := f.do("GET", "/api/v1/profiles/1/filters", f.viewer, "")
	var got []map[string]any
	_ = json.Unmarshal(raw, &got)
	if len(got) != 1 || got[0]["level"] != "relaxed" {
		t.Fatalf("filters after level change: %s", raw)
	}

	// Bad input is rejected.
	for _, body := range []string{
		`{"kind":"filter","ref":"nope","state":"block"}`,
		`{"kind":"filter","ref":"ads","state":"block","level":"ultra"}`,
		`{"kind":"filter","ref":"ads","state":"allow"}`,
		`{"kind":"service","ref":"Tik Tok","state":"block"}`,
		`{"kind":"service","ref":"tiktok","state":"redirect"}`,
		`{"kind":"bogus","ref":"x","state":"block"}`,
	} {
		if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator, body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", body, code)
		}
	}

	if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator, `{"kind":"filter","ref":"ads","state":"off"}`); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	f.waitReload()
	_, _, raw = f.do("GET", "/api/v1/profiles/1/filters", f.viewer, "")
	if string(raw) != "[]\n" {
		t.Fatalf("after disable: %s", raw)
	}
}

func TestServiceRedirectNeedsOwnExit(t *testing.T) {
	f := newFixture(t)

	// An exit in the other tenant cannot be used.
	code, body, _ := f.do("POST", "/api/v1/exits", f.otherAdmin,
		`{"name":"theirs","kind":"wireguard","address":"203.0.113.9:51820","answer_ip":"10.77.0.9"}`)
	if code != http.StatusCreated {
		t.Fatalf("other exit: %d %v", code, body)
	}
	f.waitReload()
	theirs := body["id"].(float64)
	if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator,
		`{"kind":"service","ref":"netflix","state":"redirect","exit_id":`+ftoa(theirs)+`}`); code != http.StatusNotFound {
		t.Errorf("cross-org exit: got %d, want 404", code)
	}

	code, body, _ = f.do("POST", "/api/v1/exits", f.operator,
		`{"name":"ours","kind":"wireguard","address":"203.0.113.8:51820","answer_ip":"10.77.0.8"}`)
	if code != http.StatusCreated {
		t.Fatalf("own exit: %d", code)
	}
	f.waitReload()
	ours := body["id"].(float64)
	if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.operator,
		`{"kind":"service","ref":"netflix","state":"redirect","exit_id":`+ftoa(ours)+`}`); code != http.StatusOK {
		t.Fatalf("own exit redirect: %d", code)
	}
	f.waitReload()

	// Deleting the exit drops the redirect.
	if code, _, _ := f.do("DELETE", "/api/v1/exits/"+ftoa(ours), f.operator, ""); code != http.StatusOK {
		t.Fatalf("delete exit: %d", code)
	}
	f.waitReload()
	_, _, raw := f.do("GET", "/api/v1/profiles/1/filters", f.viewer, "")
	if string(raw) != "[]\n" {
		t.Fatalf("redirect survived its exit: %s", raw)
	}
}

func TestFiltersAreOrgScoped(t *testing.T) {
	f := newFixture(t)
	if code, _, _ := f.do("GET", "/api/v1/profiles/1/filters", f.otherAdmin, ""); code != http.StatusNotFound {
		t.Errorf("other tenant reading filters: got %d, want 404", code)
	}
	if code, _, _ := f.do("PUT", "/api/v1/profiles/1/filters", f.otherAdmin, `{"kind":"filter","ref":"ads","state":"block"}`); code != http.StatusNotFound {
		t.Errorf("other tenant writing filters: got %d, want 404", code)
	}
}

func TestNewBlocklistAppliesToProfilesAndDeleteCleansUp(t *testing.T) {
	f := newFixture(t)
	code, body, _ := f.do("POST", "/api/v1/blocklists", f.operator, `{"url":"https://example.org/hosts.txt","format":"hosts"}`)
	if code != http.StatusCreated {
		t.Fatalf("add list: %d %v", code, body)
	}
	f.waitReload()
	id := ftoa(body["id"].(float64))
	_, _, raw := f.do("GET", "/api/v1/profiles/1/filters", f.viewer, "")
	var got []map[string]any
	_ = json.Unmarshal(raw, &got)
	if len(got) != 1 || got[0]["kind"] != "list" || got[0]["ref"] != id {
		t.Fatalf("new list not enabled on the profile: %s", raw)
	}
	if code, _, _ := f.do("DELETE", "/api/v1/blocklists/"+id, f.operator, ""); code != http.StatusNoContent {
		t.Fatalf("delete list: %d", code)
	}
	f.waitReload()
	_, _, raw = f.do("GET", "/api/v1/profiles/1/filters", f.viewer, "")
	if string(raw) != "[]\n" {
		t.Fatalf("list row survived delete: %s", raw)
	}
}

func TestCatalogFilters(t *testing.T) {
	f := newFixture(t)
	code, _, raw := f.do("GET", "/api/v1/catalog/filters", f.viewer, "")
	if code != http.StatusOK {
		t.Fatalf("catalog: %d", code)
	}
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil || len(got) == 0 {
		t.Fatalf("catalog body: %s", raw)
	}
	if _, leaked := got[0]["levels"].([]any)[0].(map[string]any)["URLs"]; leaked {
		t.Error("source URLs should not be serialized")
	}
}

func ftoa(f float64) string { return strconv.FormatInt(int64(f), 10) }
