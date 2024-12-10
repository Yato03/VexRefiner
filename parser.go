package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
)

type VEX struct {
	Context     string      `json:"@context"`
	ID          string      `json:"@id"`
	Author      string      `json:"author"`
	Role        string      `json:"role"`
	Timestamp   string      `json:"timestamp"`
	LastUpdated string      `json:"last_updated"`
	Version     int         `json:"version"`
	Tooling     string      `json:"tooling"`
	Statements  []Statement `json:"statements"`
}

type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Timestamp     string        `json:"timestamp"`
	LastUpdated   string        `json:"last_updated"`
	Status        string        `json:"status"`
	Justification string        `json:"justification"`
	Supplier      string        `json:"supplier"`
}

type Vulnerability struct {
	ID          string `json:"@id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// parseAndFormatTime parsea una fecha en el formato original y la convierte a RFC3339 con Z
func parseAndFormatTime(original string) (string, error) {
	layout := "2006-01-02 15:04:05.000000"
	t, err := time.Parse(layout, original)
	if err != nil {
		return "", err
	}
	rfc := t.UTC().Format(time.RFC3339Nano)
	if !strings.HasSuffix(rfc, "Z") {
		rfc = rfc + "Z"
	}
	return rfc, nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Preguntar por archivo a parsear
	fmt.Print("Archivo a parsear [por defecto vex.json]: ")
	inputFile, _ := reader.ReadString('\n')
	inputFile = strings.TrimSpace(inputFile)
	if inputFile == "" {
		inputFile = "vex.json"
	}

	// Preguntar por archivo de salida
	fmt.Print("Archivo output [por defecto vex-modificado.json]: ")
	outputFile, _ := reader.ReadString('\n')
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		outputFile = "vex-modificado.json"
	}

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error leyendo el archivo: %v\n", err)
		os.Exit(1)
	}

	var vex VEX
	err = json.Unmarshal(data, &vex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al parsear JSON: %v\n", err)
		os.Exit(1)
	}

	// Usar spinner para la animación de cargando
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // CharSet 9 es "/-\|"
	s.Prefix = "Parseando fechas del vex "
	s.Start()

	// Convertir timestamp principal
	newMainTimestamp, err := parseAndFormatTime(vex.Timestamp)
	if err != nil {
		s.Stop()
		fmt.Fprintf(os.Stderr, "\nError al formatear timestamp principal: %v\n", err)
		os.Exit(1)
	}
	newMainLastUpdated, err := parseAndFormatTime(vex.LastUpdated)
	if err != nil {
		s.Stop()
		fmt.Fprintf(os.Stderr, "\nError al formatear last_updated principal: %v\n", err)
		os.Exit(1)
	}
	vex.Timestamp = newMainTimestamp
	vex.LastUpdated = newMainLastUpdated

	// Convertir timestamps en cada statement
	for i := range vex.Statements {
		newStatementTimestamp, err := parseAndFormatTime(vex.Statements[i].Timestamp)
		if err != nil {
			s.Stop()
			fmt.Fprintf(os.Stderr, "\nError al formatear timestamp en statement %d: %v\n", i, err)
			os.Exit(1)
		}
		newStatementLastUpdated, err := parseAndFormatTime(vex.Statements[i].LastUpdated)
		if err != nil {
			s.Stop()
			fmt.Fprintf(os.Stderr, "\nError al formatear last_updated en statement %d: %v\n", i, err)
			os.Exit(1)
		}
		vex.Statements[i].Timestamp = newStatementTimestamp
		vex.Statements[i].LastUpdated = newStatementLastUpdated
	}

	outputData, err := json.MarshalIndent(vex, "", "  ")
	if err != nil {
		s.Stop()
		fmt.Fprintf(os.Stderr, "\nError al serializar a JSON: %v\n", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(outputFile, outputData, 0644)
	if err != nil {
		s.Stop()
		fmt.Fprintf(os.Stderr, "\nError al escribir el archivo: %v\n", err)
		os.Exit(1)
	}
	
	// Comprobar si todas las vulnerabilidades tienen status: not_affected
	allNotAffected := true
	for _, s := range vex.Statements {
		if s.Status != "not_affected" {
			allNotAffected = false
			break
		}
	}

	s.Stop() // Detener el spinner antes de imprimir el resultado final
	fmt.Println()

	if allNotAffected {
		// Mostrar un warning en amarillo
		fmt.Printf("\033[33mWARNING: Todas las vulnerabilidades tienen status 'not_affected', Guac no tendrá en cuenta este archivo.\033[0m\n")
	} else {
		fmt.Println("Proceso completado con éxito.")
	}
}

