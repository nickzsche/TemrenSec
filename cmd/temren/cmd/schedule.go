package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/scheduler"
	"github.com/spf13/cobra"
)

var (
	schedTarget      string
	schedName        string
	schedCron        string
	schedHourly      bool
	schedDaily       bool
	schedWeekly      bool
	schedMonthly     bool
	schedDepth       int
	schedMaxPages    int
	schedConcurrency int
	schedRateLimit   int
	schedTimeout     int
	schedActive      bool
	schedPassive     bool
	schedAuthToken   string
	schedAuthType    string
	schedWAFBypass   bool
	schedHeadless    bool
	schedFormat      string
	schedVerify      bool
	schedSBOM        bool
	schedNotifySlack   string
	schedNotifyDiscord string
	schedNotifyTeams   string
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scheduled scans",
	Long: `Manage recurring security scans.

Examples:
  temren schedule create --target https://example.com --daily --name "Daily Scan"
  temren schedule create --target https://example.com --cron "0 2 * * *" --name "Custom Scan"
  temren schedule list
  temren schedule delete <schedule-id>
  temren schedule enable <schedule-id>
  temren schedule disable <schedule-id>
  temren schedule run <schedule-id>
`,
}

var scheduleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new scheduled scan",
	Run:   runScheduleCreate,
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scheduled scans",
	Run:   runScheduleList,
}

var scheduleDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a scheduled scan",
	Args:  cobra.ExactArgs(1),
	Run:   runScheduleDelete,
}

var scheduleEnableCmd = &cobra.Command{
	Use:   "enable [id]",
	Short: "Enable a scheduled scan",
	Args:  cobra.ExactArgs(1),
	Run:   runScheduleEnable,
}

var scheduleDisableCmd = &cobra.Command{
	Use:   "disable [id]",
	Short: "Disable a scheduled scan",
	Args:  cobra.ExactArgs(1),
	Run:   runScheduleDisable,
}

var scheduleRunCmd = &cobra.Command{
	Use:   "run [id]",
	Short: "Run a scheduled scan immediately",
	Args:  cobra.ExactArgs(1),
	Run:   runScheduleRun,
}

func init() {
	rootCmd.AddCommand(scheduleCmd)
	scheduleCmd.AddCommand(scheduleCreateCmd)
	scheduleCmd.AddCommand(scheduleListCmd)
	scheduleCmd.AddCommand(scheduleDeleteCmd)
	scheduleCmd.AddCommand(scheduleEnableCmd)
	scheduleCmd.AddCommand(scheduleDisableCmd)
	scheduleCmd.AddCommand(scheduleRunCmd)

	scheduleCreateCmd.Flags().StringVarP(&schedTarget, "target", "t", "", "Target URL to scan (required)")
	scheduleCreateCmd.Flags().StringVarP(&schedName, "name", "n", "", "Name for the schedule")
	scheduleCreateCmd.Flags().StringVar(&schedCron, "cron", "", "Custom cron expression (e.g., '0 2 * * *')")
	scheduleCreateCmd.Flags().BoolVar(&schedHourly, "hourly", false, "Run scan every hour")
	scheduleCreateCmd.Flags().BoolVar(&schedDaily, "daily", false, "Run scan daily at 2 AM UTC")
	scheduleCreateCmd.Flags().BoolVar(&schedWeekly, "weekly", false, "Run scan weekly on Mondays at 2 AM UTC")
	scheduleCreateCmd.Flags().BoolVar(&schedMonthly, "monthly", false, "Run scan monthly on the 1st at 2 AM UTC")
	scheduleCreateCmd.Flags().IntVar(&schedDepth, "depth", 2, "Maximum crawl depth")
	scheduleCreateCmd.Flags().IntVar(&schedMaxPages, "max-pages", 50, "Maximum pages to crawl")
	scheduleCreateCmd.Flags().IntVar(&schedConcurrency, "concurrency", 5, "Number of concurrent workers")
	scheduleCreateCmd.Flags().IntVar(&schedRateLimit, "rate", 10, "Requests per second")
	scheduleCreateCmd.Flags().IntVar(&schedTimeout, "timeout", 30, "Request timeout in seconds")
	scheduleCreateCmd.Flags().BoolVar(&schedActive, "active", true, "Enable active vulnerability scanning")
	scheduleCreateCmd.Flags().BoolVar(&schedPassive, "passive", true, "Enable passive security analysis")
	scheduleCreateCmd.Flags().StringVar(&schedAuthToken, "auth-token", "", "Bearer token for authenticated scanning")
	scheduleCreateCmd.Flags().StringVar(&schedAuthType, "auth-type", "bearer", "Auth type: bearer, basic, cookie, header")
	scheduleCreateCmd.Flags().BoolVar(&schedWAFBypass, "waf-bypass", false, "Enable WAF bypass techniques")
	scheduleCreateCmd.Flags().BoolVar(&schedHeadless, "headless", false, "Enable headless browser for SPA/JS rendering")
	scheduleCreateCmd.Flags().StringVarP(&schedFormat, "format", "f", "json", "Output format: json, sarif, html")
	scheduleCreateCmd.Flags().BoolVar(&schedVerify, "verify", false, "Verify findings with proof-based exploitation")
	scheduleCreateCmd.Flags().BoolVar(&schedSBOM, "sbom", false, "Generate Software Bill of Materials")
	scheduleCreateCmd.Flags().StringVar(&schedNotifySlack, "notify-slack", "", "Slack webhook URL for notifications")
	scheduleCreateCmd.Flags().StringVar(&schedNotifyDiscord, "notify-discord", "", "Discord webhook URL for notifications")
	scheduleCreateCmd.Flags().StringVar(&schedNotifyTeams, "notify-teams", "", "Microsoft Teams webhook URL for notifications")

	scheduleCreateCmd.MarkFlagRequired("target")
}

func getRecurrence() string {
	if schedHourly {
		return "hourly"
	}
	if schedDaily {
		return "daily"
	}
	if schedWeekly {
		return "weekly"
	}
	if schedMonthly {
		return "monthly"
	}
	if schedCron != "" {
		return "custom"
	}
	return "daily"
}

func newScheduleManager() *scheduler.ScheduleManager {
	cfg := &httpengine.Config{
		Timeout:         30 * time.Second,
		RateLimit:       10,
		MaxRedirects:    10,
		FollowRedirects: true,
		UserAgent:       "TemrenSec/1.0 (Scheduler)",
	}
	client := httpengine.NewClient(cfg)
	return scheduler.NewScheduleManager(client)
}

func runScheduleCreate(cmd *cobra.Command, args []string) {
	if schedTarget == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		os.Exit(1)
	}

	recurrence := getRecurrence()

	schedule := &scheduler.ScanSchedule{
		Name:       schedName,
		TargetURL:  schedTarget,
		CronExpr:   schedCron,
		Recurrence: recurrence,
		ScanConfig: scheduler.ScanConfig{
			Depth:         schedDepth,
			MaxPages:      schedMaxPages,
			Concurrency:   schedConcurrency,
			RateLimit:     schedRateLimit,
			Timeout:       schedTimeout,
			Active:        schedActive,
			Passive:       schedPassive,
			AuthToken:     schedAuthToken,
			AuthType:      schedAuthType,
			WAFBypass:     schedWAFBypass,
			Headless:      schedHeadless,
			Format:        schedFormat,
			Verify:        schedVerify,
			SBOM:          schedSBOM,
			NotifySlack:   schedNotifySlack,
			NotifyDiscord: schedNotifyDiscord,
			NotifyTeams:   schedNotifyTeams,
		},
		Enabled: true,
	}

	sm := newScheduleManager()
	if err := sm.CreateSchedule(schedule); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating schedule: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Schedule created successfully!\n")
	fmt.Printf("  ID:        %s\n", schedule.ID)
	fmt.Printf("  Name:      %s\n", schedule.Name)
	fmt.Printf("  Target:    %s\n", schedule.TargetURL)
	fmt.Printf("  Recurrence: %s\n", schedule.Recurrence)
	if schedule.CronExpr != "" {
		fmt.Printf("  Cron:      %s\n", schedule.CronExpr)
	}
	fmt.Printf("  Next Run:  %s\n", schedule.NextRun.Format(time.RFC3339))
	fmt.Printf("  Enabled:   %v\n", schedule.Enabled)
}

func runScheduleList(cmd *cobra.Command, args []string) {
	sm := newScheduleManager()
	schedules := sm.ListSchedules()

	if len(schedules) == 0 {
		fmt.Println("No scheduled scans found.")
		return
	}

	data, err := json.MarshalIndent(schedules, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling schedules: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func runScheduleDelete(cmd *cobra.Command, args []string) {
	id := args[0]
	sm := newScheduleManager()

	if err := sm.DeleteSchedule(id); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting schedule: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Schedule %s deleted successfully.\n", id)
}

func runScheduleEnable(cmd *cobra.Command, args []string) {
	id := args[0]
	sm := newScheduleManager()

	if err := sm.EnableSchedule(id); err != nil {
		fmt.Fprintf(os.Stderr, "Error enabling schedule: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Schedule %s enabled.\n", id)
}

func runScheduleDisable(cmd *cobra.Command, args []string) {
	id := args[0]
	sm := newScheduleManager()

	if err := sm.DisableSchedule(id); err != nil {
		fmt.Fprintf(os.Stderr, "Error disabling schedule: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Schedule %s disabled.\n", id)
}

func runScheduleRun(cmd *cobra.Command, args []string) {
	id := args[0]
	sm := newScheduleManager()

	schedule, err := sm.GetSchedule(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running schedule: %s (%s)\n", schedule.Name, schedule.TargetURL)
	fmt.Printf("This may take a while...\n\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := sm.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting scheduler: %v\n", err)
		os.Exit(1)
	}

	sm.RunSchedule(schedule)

	select {
	case result := <-sm.Results():
		fmt.Printf("Scan completed for %s\n", result.TargetURL)
		fmt.Printf("  Findings: %d\n", len(result.Findings))
		if result.Error != "" {
			fmt.Printf("  Error: %s\n", result.Error)
		}
		for _, f := range result.Findings {
			fmt.Printf("  [%s] %s - %s\n", f.Severity, f.Title, f.URL)
		}
	default:
		fmt.Println("Scan completed but no results received.")
	}

	sm.Stop()
}