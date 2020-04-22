package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type data struct {
	source      []string
	dest        string
	protocol    string
	description string
	port        string
	direction   string
}

const (
	region   string = "us-east-2"
	inbound  string = "inbound"
	outbound string = "outbound"
)

func main() {
	start := time.Now()
	cfg, err := external.LoadDefaultAWSConfig(
		external.WithDefaultRegion(region),
	)
	defer errRecover()
	if err != nil {
		panic(err)
	}
	file := flag.String("source", "", "please pass in csv file location")
	flag.Parse()
	if *file == "" {
		fmt.Println("source flag is required")
		flag.PrintDefaults()
		os.Exit(1)
	}
	sgch := make(chan string)
	csch := make(chan []data)
	gtch := make(chan ec2.SecurityGroup)
	ibch := make(chan *ec2.AuthorizeSecurityGroupIngressOutput)
	obch := make(chan *ec2.AuthorizeSecurityGroupEgressOutput)
	go readCSV(*file, csch)
	inboundDATA := <-csch
	outboundDATA := <-csch
	insgID := ""
	outsgID := ""
	for i, v := range inboundDATA {
		if i == 0 {
			go getSGfromIP(cfg, v.dest, sgch)
			insgID = <-sgch
		} else if v.dest != inboundDATA[i-1].dest {
			go getSGfromIP(cfg, v.dest, sgch)
			insgID = <-sgch
		}
		port, err := strconv.ParseInt(v.port, 10, 64)
		if err != nil {
			panic(err)
		}
		go createInboundSGRule(cfg, v.protocol, insgID, v.description, v.source, port, ibch)
		go getSGRules(cfg, insgID, gtch)
	}
	for i, v := range outboundDATA {
		if i == 0 {
			go getSGfromIP(cfg, v.dest, sgch)
			outsgID = <-sgch
		} else if v.dest != outboundDATA[i-1].dest {
			go getSGfromIP(cfg, v.dest, sgch)
			outsgID = <-sgch
		}
		port, err := strconv.ParseInt(v.port, 10, 64)
		if err != nil {
			panic(err)
		}
		go createOutBoundSGRule(cfg, v.protocol, outsgID, v.description, v.source, port, obch)
		go getSGRules(cfg, outsgID, gtch)
	}

	for range inboundDATA {
		select {
		case <-ibch:
			fmt.Printf("%s Rule created successfully\n", inbound)
		case sgRule := <-gtch:
			fmt.Println(sgRule)
		}
	}

	for range outboundDATA {
		select {
		case <-obch:
			fmt.Printf("%s Rule created successfully\n", outbound)
		case sgRule := <-gtch:
			fmt.Println(sgRule)
		}
	}
	finish := time.Now().Sub(start).Seconds()
	fmt.Printf("time took: %.2f seconds\n", finish)
}

func readCSV(pathTocsv string, ch chan []data) {
	finfo, err := os.Stat(pathTocsv)
	defer errRecover()
	if err != nil {
		if os.IsNotExist(err) {
			panic(errors.New("File does not exist, in the mentioned path"))
		}
	}
	file, err := os.Open(finfo.Name())
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	allRecords, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}
	parseINBdata := make([]data, 0)
	parseOUTBdata := make([]data, 0)

	for index, row := range allRecords {
		if index == 0 {
			continue
		}
		switch bound := strings.TrimSpace(row[5]); bound {
		case inbound:
			parseINBdata = append(parseINBdata, data{
				dest:        row[0],
				protocol:    row[1],
				description: row[2],
				port:        row[3],
				source:      strings.Split(strings.TrimSpace(row[4]), " "),
				direction:   bound,
			})
		case outbound:
			parseOUTBdata = append(parseOUTBdata, data{
				dest:        row[0],
				protocol:    row[1],
				description: row[2],
				port:        row[3],
				source:      strings.Split(strings.TrimSpace(row[4]), " "),
				direction:   bound,
			})
		}
	}
	ch <- parseINBdata
	ch <- parseOUTBdata
}

func getSGfromIP(cfg aws.Config, ip string, ch chan string) {
	NIC := ec2.New(cfg)
	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2.Filter{
			{
				Name:   aws.String("addresses.private-ip-address"),
				Values: []string{ip},
			},
		},
	}
	req := NIC.DescribeNetworkInterfacesRequest(input)
	res, err := req.Send(context.Background())
	if err != nil {
		panic(err)
	}
	ch <- *res.NetworkInterfaces[0].Groups[0].GroupId
}

func createInboundSGRule(cfg aws.Config, protocol, sgID, desc string, ip []string, port int64, ch chan *ec2.AuthorizeSecurityGroupIngressOutput) {
	SGR := ec2.New(cfg)
	ips := make([]ec2.IpRange, 0)
	defer errRecover()
	if len(ip) > 1 {
		for i := range ip {
			if strings.Contains(ip[i], "/") {
				ips = append(ips, ec2.IpRange{

					CidrIp:      aws.String(ip[i]),
					Description: aws.String(desc),
				})
			} else {
				ips = append(ips, ec2.IpRange{

					CidrIp:      aws.String(fmt.Sprintf("%s/32", ip[i])),
					Description: aws.String(desc),
				})
			}
		}
	} else {
		if strings.Contains(ip[0], "/") {
			ips = append(ips, ec2.IpRange{

				CidrIp:      aws.String(ip[0]),
				Description: aws.String(desc),
			})
		} else {
			ips = append(ips, ec2.IpRange{

				CidrIp:      aws.String(fmt.Sprintf("%s/32", ip[0])),
				Description: aws.String(desc),
			})
		}
	}
	input := &ec2.AuthorizeSecurityGroupIngressInput{
		IpPermissions: []ec2.IpPermission{
			{
				IpProtocol: aws.String(protocol),
				FromPort:   aws.Int64(port),
				IpRanges:   ips,
				ToPort:     aws.Int64(port),
			},
		},
		GroupId: aws.String(sgID),
	}
	req := SGR.AuthorizeSecurityGroupIngressRequest(input)
	res, err := req.Send(context.Background())
	if err != nil {
		panic(err)
	}
	ch <- res.AuthorizeSecurityGroupIngressOutput
}

func createOutBoundSGRule(cfg aws.Config, protocol, sgID, desc string, ip []string, port int64, ch chan *ec2.AuthorizeSecurityGroupEgressOutput) {
	SGR := ec2.New(cfg)
	ips := make([]ec2.IpRange, 0)
	defer errRecover()
	if len(ip) > 1 {
		for i := range ip {
			if strings.Contains(ip[i], "/") {
				ips = append(ips, ec2.IpRange{

					CidrIp:      aws.String(ip[i]),
					Description: aws.String(desc),
				})
			} else {
				ips = append(ips, ec2.IpRange{

					CidrIp:      aws.String(fmt.Sprintf("%s/32", ip[i])),
					Description: aws.String(desc),
				})
			}
		}
	} else {
		if strings.Contains(ip[0], "/") {
			ips = append(ips, ec2.IpRange{

				CidrIp:      aws.String(ip[0]),
				Description: aws.String(desc),
			})
		} else {
			ips = append(ips, ec2.IpRange{

				CidrIp:      aws.String(fmt.Sprintf("%s/32", ip[0])),
				Description: aws.String(desc),
			})
		}
	}
	input := &ec2.AuthorizeSecurityGroupEgressInput{
		IpPermissions: []ec2.IpPermission{
			{
				IpProtocol: aws.String(protocol),
				FromPort:   aws.Int64(port),
				IpRanges:   ips,
				ToPort:     aws.Int64(port),
			},
		},
		GroupId: aws.String(sgID),
	}
	req := SGR.AuthorizeSecurityGroupEgressRequest(input)
	res, err := req.Send(context.Background())
	if err != nil {
		panic(err)
	}
	ch <- res.AuthorizeSecurityGroupEgressOutput
}

func getSGRules(cfg aws.Config, sgid string, ch chan ec2.SecurityGroup) {
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgid},
	}
	client := ec2.New(cfg)
	defer errRecover()
	req := client.DescribeSecurityGroupsRequest(input)
	res, err := req.Send(context.Background())
	if err != nil {
		panic(err)
	}
	ch <- res.SecurityGroups[len(res.SecurityGroups)-1]
}

func errRecover() {
	if r := recover(); r != nil {
		fmt.Println("An error has occured:")
		fmt.Printf("%s\n\n", strings.Repeat("💀", 50))
		fmt.Println(r)
		fmt.Printf("\n")
		fmt.Println(strings.Repeat("💀", 50))
		//os.Exit(1) optional, if you want to stop the excution if error occurs.
	}
}
