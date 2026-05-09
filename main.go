package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const defaultConfigPath = "/etc/mtban/mtban.conf"

type options struct {
	Action  string
	IP      string
	List    string
	Timeout string
	Comment string
	Config  string
}

func main() {
	logger, _ := syslog.New(syslog.LOG_USER|syslog.LOG_INFO, "mtban")

	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		logFailure(logger, "", "", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfg, err := loadConfig(opts.Config)
	if err != nil {
		logFailure(logger, opts.Action, opts.IP, err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	existingID, err := findID(client, cfg, opts.List, opts.IP)
	if err != nil {
		logFailure(logger, opts.Action, opts.IP, err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch opts.Action {
	case "ban":
		err = ban(client, cfg, opts, existingID)
	case "unban":
		err = unban(client, cfg, existingID)
	default:
		err = fmt.Errorf("unknown action: %s", opts.Action)
	}

	if err != nil {
		logFailure(logger, opts.Action, opts.IP, err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logInfo(logger, fmt.Sprintf("%s %s OK", opts.Action, opts.IP))
}

func parseArgs(args []string) (options, error) {
	opts := options{
		List:    "blocked",
		Timeout: "",
		Comment: "mtban",
		Config:  defaultConfigPath,
	}

	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--help" || arg == "-h" {
			return opts, errors.New("usage: mtban [--list NAME] [--timeout DURATION] [--comment TEXT] [--config FILE] <ban|unban> <ip>")
		}

		if strings.HasPrefix(arg, "--") {
			name, value, hasInlineValue := strings.Cut(arg[2:], "=")
			if !hasInlineValue {
				i++
				if i >= len(args) {
					return opts, fmt.Errorf("missing value for --%s", name)
				}
				value = args[i]
			}

			switch name {
			case "list":
				opts.List = value
			case "timeout":
				opts.Timeout = value
			case "comment":
				opts.Comment = value
			case "config":
				opts.Config = value
			default:
				return opts, fmt.Errorf("unknown option: --%s", name)
			}
			continue
		}

		if strings.HasPrefix(arg, "-") {
			return opts, fmt.Errorf("unknown option: %s", arg)
		}

		positionals = append(positionals, arg)
	}

	if len(positionals) != 2 {
		return opts, errors.New("usage: mtban [--list NAME] [--timeout DURATION] [--comment TEXT] [--config FILE] <ban|unban> <ip>")
	}

	opts.Action = positionals[0]
	opts.IP = positionals[1]

	if opts.Action != "ban" && opts.Action != "unban" {
		return opts, errors.New("action must be 'ban' or 'unban'")
	}

	if opts.IP == "" {
		return opts, errors.New("ip must not be empty")
	}

	return opts, nil
}

func loadConfig(configPath string) (map[string]string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}

	cfg := map[string]string{}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		cfg[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	for _, required := range []string{"url", "username", "password"} {
		if cfg[required] == "" {
			return nil, fmt.Errorf("missing required config key: %s", required)
		}
	}

	return cfg, nil
}

func findID(client *http.Client, cfg map[string]string, listName, ip string) (string, error) {
	query := url.Values{}
	query.Set("list", listName)
	query.Set("address", ip)

	resp, err := api(client, cfg, http.MethodGet, "ip/firewall/address-list?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}

	if len(resp) == 0 {
		return "", nil
	}

	id, _ := resp[0][".id"].(string)
	return id, nil
}

func ban(client *http.Client, cfg map[string]string, opts options, existingID string) error {
	if existingID != "" {
		patch := map[string]string{"comment": opts.Comment}
		if opts.Timeout != "" {
			patch["timeout"] = opts.Timeout
		}
		_, err := api(client, cfg, http.MethodPatch, "ip/firewall/address-list/"+existingID, patch)
		return err
	}

	data := map[string]string{
		"list":    opts.List,
		"address": opts.IP,
		"comment": opts.Comment,
	}
	if opts.Timeout != "" {
		data["timeout"] = opts.Timeout
	}

	_, err := api(client, cfg, http.MethodPut, "ip/firewall/address-list", data)
	return err
}

func unban(client *http.Client, cfg map[string]string, existingID string) error {
	if existingID == "" {
		return nil
	}

	_, err := api(client, cfg, http.MethodDelete, "ip/firewall/address-list/"+existingID, nil)
	return err
}

func api(
	client *http.Client,
	cfg map[string]string,
	method string,
	apiPath string,
	data map[string]string,
) ([]map[string]any, error) {
	baseURL := strings.TrimRight(cfg["url"], "/")
	endpoint := baseURL + "/rest/" + path.Clean("/" + apiPath)[1:]

	if strings.Contains(apiPath, "?") {
		endpoint = baseURL + "/rest/" + apiPath
	}

	var body io.Reader
	if data != nil {
		payload, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("encode request payload: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(cfg["username"] + ":" + cfg["password"]))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if res.StatusCode >= 400 {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" {
			return nil, fmt.Errorf("api returned status %s", res.Status)
		}
		return nil, fmt.Errorf("api returned status %s: %s", res.Status, trimmed)
	}

	if len(raw) == 0 {
		return nil, nil
	}

	var parsed []map[string]any
	if err := json.Unmarshal(raw, &parsed); err == nil {
		return parsed, nil
	}

	var single map[string]any
	if err := json.Unmarshal(raw, &single); err == nil {
		return []map[string]any{single}, nil
	}

	return nil, nil
}

func logInfo(logger *syslog.Writer, msg string) {
	if logger != nil {
		_ = logger.Info(msg)
	}
}

func logFailure(logger *syslog.Writer, action, ip string, err error) {
	if logger == nil {
		return
	}
	if action == "" || ip == "" {
		_ = logger.Err(fmt.Sprintf("FAILED: %v", err))
		return
	}
	_ = logger.Err(fmt.Sprintf("%s %s FAILED: %v", action, ip, err))
}
