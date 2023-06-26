package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type CodeIssueCollection struct {
	XMLName    xml.Name    `xml:"CodeIssueCollection"`
	CodeIssues []CodeIssue `xml:"CodeIssue"`
}

type CodeIssue struct {
	XMLName     xml.Name `xml:"CodeIssue"`
	Title       string   `xml:"Title"`
	Description string   `xml:"Description"`
	Priority    string   `xml:"Priority"`
	Severity    string   `xml:"Severity"`
	FileName    string   `xml:"FileName"`
	Line        string   `xml:"Line"`
	CodeLine    string   `xml:"CodeLine"`
	Checked     string   `xml:"Checked"`
	CheckColour string   `xml:"CheckColour"`
}

type PrismBaseFile struct {
	Version int         `json:"version"`
	Issues  []PrismItem `json:"issues"`
}

type PrismItem struct {
	Name                    string      `json:"name"`
	OriginalRiskRating      string      `json:"original_risk_rating"`
	ClientDefinedRiskRating string      `json:"client_defined_risk_rating"`
	Finding                 string      `json:"finding"`
	Recommendation          string      `json:"recommendation"`
	CvssVector              string      `json:"cvss_vector"`
	AffectedHosts           []PrismHost `json:"affected_hosts"`
	TechnicalDetails        string      `json:"technical_details"`
}

type PrismHost struct {
	Name string `json:"name"`
}

func main() {
	var filename = os.Args[1]
	fmt.Println("Looking for NCC File: " + filename)

	nccResult := parseNccFile(filename)
	prismResult := nccToPrism(nccResult)

	data, _ := json.Marshal(prismResult)

	var finalFilename = strings.Split(filename, ".")[0]

	fmt.Println("Creating File: " + finalFilename + "_prism.json")
	f, _ := os.Create(finalFilename + "_prism.json")
	f.WriteString(string(data))
	f.Sync()
}

func parseNccFile(filename string) CodeIssueCollection {
	xmlFile, err := os.Open(filename)

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("File found")
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)

	var result CodeIssueCollection
	xml.Unmarshal([]byte(byteValue), &result)

	return result
}

func nccToPrism(baseFile CodeIssueCollection) PrismBaseFile {
	var prismFile PrismBaseFile

	prismFile.Version = 1

	for _, codeIssue := range baseFile.CodeIssues {
		fileLocation := strings.Split(codeIssue.FileName, "\\")

		var prismHost PrismHost
		prismHost.Name = fileLocation[len(fileLocation)-1]

		var prismItem PrismItem
		prismItem.Name = codeIssue.Title
		prismItem.Finding = codeIssue.Description
		prismItem.ClientDefinedRiskRating = parseRiskRating(codeIssue.Severity)
		prismItem.OriginalRiskRating = parseRiskRating(codeIssue.Severity)
		prismItem.TechnicalDetails = parseTechnicalDetails(codeIssue)

		prismItem.AffectedHosts = append(prismItem.AffectedHosts, prismHost)
		prismFile.Issues = append(prismFile.Issues, prismItem)
	}

	return prismFile
}

func parseTechnicalDetails(issue CodeIssue) string {
	var techDetails = "<h3>Affected Packages</h3>"
	techDetails = "<table><thead><tr><th>File</th><th>Line</th><th>Codeline</th></tr></thead><tbody>"

	techDetails += "<tr><td>" + issue.FileName + "</td>" + "<td>" + issue.Line + "</td><td>" + issue.CodeLine + "</td>"
	techDetails += "</tbody></table>"

	return techDetails
}

func parseRiskRating(riskRating string) string {
	if riskRating == "Critical" {
		return "Critical"
	}

	log.Fatal("Error Parsing Unknown Risk Rating: " + riskRating)

	panic("Invalid Risk Rating")
}
