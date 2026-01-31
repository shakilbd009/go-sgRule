package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Rule represents a security group rule from CSV
type Rule struct {
	Source      []string
	Dest        string
	Protocol    string
	Description string
	Port        string
	Direction   string
}

const (
	inbound  = "inbound"
	outbound = "outbound"
)

func main() {
	logger := log.New(os.Stdout, "[sgRule] ", log.LstdFlags|log.Lshortfile)
	start := time.Now()

	// Load configuration
	region := getEnv("AWS_REGION", "us-east-2")
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		logger.Fatalf("Failed to load AWS config: %v", err)
	}

	// Parse command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	csvPath := os.Args[1]
	
	// Validate CSV file exists
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		logger.Fatalf("CSV file not found: %s", csvPath)
	}

	logger.Printf("Processing security group rules from: %s", csvPath)

	// Read and parse CSV
	rules, err := readCSV(csvPath)
	if err != nil {
		logger.Fatalf("Failed to read CSV: %v", err)
	}

	// Separate inbound and outbound rules
	inboundRules := filterRules(rules, inbound)
	outboundRules := filterRules(rules, outbound)

	logger.Printf("Found %d inbound and %d outbound rules", len(inboundRules), len(outboundRules))

	// Process rules concurrently
	if err := processRules(cfg, inboundRules, outboundRules, logger); err != nil {
		logger.Fatalf("Failed to process rules: %v", err)
	}

	elapsed := time.Since(start).Seconds()
	logger.Printf("Completed in %.2f seconds", elapsed)
}

func printUsage() {
	fmt.Println("Usage: go-sgrule <path-to-csv-file>")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  AWS_REGION    AWS region (default: us-east-2)")
	fmt.Println()
	fmt.Println("CSV Format:")
	fmt.Println("  dest_ip,protocol,description,port,source_ips,direction")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  10.0.1.10,tcp,Web server,80,0.0.0.0/24,inbound")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func readCSV(path string) ([]Rule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("reading CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must have header and at least one data row")
	}

	var rules []Rule
	for i, row := range records {
		if i == 0 {
			continue // Skip header
		}
		
		if len(row) < 6 {
			return nil, fmt.Errorf("row %d: expected 6 columns, got %d", i, len(row))
		}

		rule := Rule{
			Dest:        strings.TrimSpace(row[0]),
			Protocol:    strings.TrimSpace(row[1]),
			Description: strings.TrimSpace(row[2]),
			Port:        strings.TrimSpace(row[3]),
			Source:      parseSourceIPs(row[4]),
			Direction:   strings.ToLower(strings.TrimSpace(row[5])),
		}
		
		rules = append(rules, rule)
	}

	return rules, nil
}

func parseSourceIPs(source string) []string {
	ips := strings.Split(strings.TrimSpace(source), " ")
	var result []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			result = append(result, ip)
		}
	}
	return result
}

func filterRules(rules []Rule, direction string) []Rule {
	var filtered []Rule
	for _, rule := range rules {
		if rule.Direction == direction {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func processRules(cfg aws.Config, inbound, outbound []Rule, logger *log.Logger) error {
	client := ec2.NewFromConfig(cfg)
	ctx := context.Background()

	// Process inbound rules
	for _, rule := range inbound {
		if err := processInboundRule(ctx, client, rule, logger); err != nil {
			logger.Printf("Failed to process inbound rule for %s: %v", rule.Dest, err)
		}
	}

	// Process outbound rules
	for _, rule := range outbound {
		if err := processOutboundRule(ctx, client, rule, logger); err != nil {
			logger.Printf("Failed to process outbound rule for %s: %v", rule.Dest, err)
		}
	}

	return nil
}

func processInboundRule(ctx context.Context, client *ec2.Client, rule Rule, logger *log.Logger) error {
	sgID, err := getSecurityGroupID(ctx, client, rule.Dest)
	if err != nil {
		return fmt.Errorf("finding security group: %w", err)
	}

	port, err := strconv.ParseInt(rule.Port, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing port %s: %w", rule.Port, err)
	}

	ipRanges := buildIPRanges(rule.Source, rule.Description)
	
	input := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String(rule.Protocol),
				FromPort:   aws.Int64(port),
				ToPort:     aws.Int64(port),
				IpRanges:   ipRanges,
			},
		},
	}

	_, err = client.AuthorizeSecurityGroupIngress(ctx, input)
	if err != nil {
		return fmt.Errorf("creating ingress rule: %w", err)
	}

	logger.Printf("Created inbound rule: %s:%d (%s)", rule.Dest, port, rule.Protocol)
	return nil
}

func processOutboundRule(ctx context.Context, client *ec2.Client, rule Rule, logger *log.Logger) error {
	sgID, err := getSecurityGroupID(ctx, client, rule.Dest)
	if err != nil {
		return fmt.Errorf("finding security group: %w", err)
	}

	port, err := strconv.ParseInt(rule.Port, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing port %s: %w", rule.Port, err)
	}

	ipRanges := buildIPRanges(rule.Source, rule.Description)
	
	input := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String(rule.Protocol),
				FromPort:   aws.Int64(port),
				ToPort:     aws.Int64(port),
				IpRanges:   ipRanges,
			},
		},
	}

	_, err = client.AuthorizeSecurityGroupEgress(ctx, input)
	if err != nil {
		return fmt.Errorf("creating egress rule: %w", err)
	}

	logger.Printf("Created outbound rule: %s:%d (%s)", rule.Dest, port, rule.Protocol)
	return nil
}

func getSecurityGroupID(ctx context.Context, client *ec2.Client, ip string) (string, error) {
	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("addresses.private-ip-address"),
				Values: []string{ip},
			},
		},
	}

	result, err := client.DescribeNetworkInterfaces(ctx, input)
	if err != nil {
		return "", fmt.Errorf("describing network interfaces: %w", err)
	}

	if len(result.NetworkInterfaces) == 0 {
		return "", fmt.Errorf("no network interface found for IP %s", ip)
	}

	if len(result.NetworkInterfaces[0].Groups) == 0 {
		return "", fmt.Errorf("no security group attached to network interface for IP %s", ip)
	}

	return *result.NetworkInterfaces[0].Groups[0].GroupId, nil
}

func buildIPRanges(ips []string, description string) []types.IpRange {
	var ranges []types.IpRange
	
	for _, ip := range ips {
		cidr := ip
		if !strings.Contains(ip, "/") {
			cidr = fmt.Sprintf("%s/32", ip)
		}
		
		ranges = append(ranges, types.IpRange{
			CidrIp:      aws.String(cidr),
			Description: aws.String(description),
		})
	}
	
	return ranges
}
