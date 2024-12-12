package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
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

// processFile procesa un solo archivo vex.json y genera el archivo modificado
func processFile(inputFile, outputFile string) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error leyendo el archivo %s: %v", inputFile, err)
	}

	var vex VEX
	err = json.Unmarshal(data, &vex)
	if err != nil {
		return fmt.Errorf("error al parsear JSON en %s: %v", inputFile, err)
	}

	// Convertir timestamp principal
	newMainTimestamp, err := parseAndFormatTime(vex.Timestamp)
	if err != nil {
		return fmt.Errorf("error al formatear timestamp principal en %s: %v", inputFile, err)
	}
	newMainLastUpdated, err := parseAndFormatTime(vex.LastUpdated)
	if err != nil {
		return fmt.Errorf("error al formatear last_updated principal en %s: %v", inputFile, err)
	}
	vex.Timestamp = newMainTimestamp
	vex.LastUpdated = newMainLastUpdated

	// Convertir timestamps en cada statement
	for i := range vex.Statements {
		newStatementTimestamp, err := parseAndFormatTime(vex.Statements[i].Timestamp)
		if err != nil {
			return fmt.Errorf("error al formatear timestamp en statement %d de %s: %v", i, inputFile, err)
		}
		newStatementLastUpdated, err := parseAndFormatTime(vex.Statements[i].LastUpdated)
		if err != nil {
			return fmt.Errorf("error al formatear last_updated en statement %d de %s: %v", i, inputFile, err)
		}
		vex.Statements[i].Timestamp = newStatementTimestamp
		vex.Statements[i].LastUpdated = newStatementLastUpdated
	}

	outputData, err := json.MarshalIndent(vex, "", "  ")
	if err != nil {
		return fmt.Errorf("error al serializar a JSON en %s: %v", inputFile, err)
	}

	err = ioutil.WriteFile(outputFile, outputData, 0644)
	if err != nil {
		return fmt.Errorf("error al escribir el archivo %s: %v", outputFile, err)
	}

	// Comprobar si todas las vulnerabilidades tienen status: not_affected
	allNotAffected := true
	for _, s := range vex.Statements {
		if s.Status != "not_affected" {
			allNotAffected = false
			break
		}
	}

	if allNotAffected {
		// Mostrar un warning en amarillo
		fmt.Printf("\033[33mWARNING: Todas las vulnerabilidades en %s tienen status 'not_affected', Guac no tendrá en cuenta este archivo.\033[0m\n", inputFile)
	} else {
		fmt.Printf("Proceso completado con éxito para %s.\n", inputFile)
	}

	return nil
}

func main() {
	// Definir la bandera -folder
	folderFlag := flag.Bool("folder", false, "Procesar todos los archivos vex.json en el directorio actual y subdirectorios")
	flag.Parse()

	if *folderFlag {
		// Procesar múltiples archivos de forma recursiva
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error obteniendo el directorio actual: %v\n", err)
			os.Exit(1)
		}

		var vexFiles []string

		// Recorrer directorios de forma recursiva para encontrar todos los vex.json
		err = filepath.WalkDir(currentDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Si hay un error al acceder a un archivo/directorio, lo ignoramos y continuamos
				fmt.Fprintf(os.Stderr, "Error accediendo a %s: %v\n", path, err)
				return nil
			}
			if !d.IsDir() && d.Name() == "vex.json" {
				vexFiles = append(vexFiles, path)
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al recorrer los directorios: %v\n", err)
			os.Exit(1)
		}

		if len(vexFiles) == 0 {
			fmt.Println("No se encontraron archivos 'vex.json' en el directorio actual ni en sus subdirectorios.")
			os.Exit(0)
		}

		// Configurar el spinner
		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // CharSet 9 es "/-\|"
		s.Prefix = fmt.Sprintf("Procesando archivos: 0/%d", len(vexFiles))
		s.Start()

		for idx, file := range vexFiles {
			// Actualizar el prefix del spinner
			s.Prefix = fmt.Sprintf("Procesando archivos: %d/%d - %s", idx+1, len(vexFiles), filepath.Base(file))
			// Determinar el archivo de salida en el mismo directorio
			dir := filepath.Dir(file)
			outputFile := filepath.Join(dir, "vex-modificado.json")
			err := processFile(file, outputFile)
			if err != nil {
				s.Stop()
				fmt.Fprintf(os.Stderr, "\n%s\n", err)
				// Reiniciar el spinner después de un error
				s.Start()
				continue // Continuar con el siguiente archivo
			}
		}

		s.Stop()
		fmt.Println("Todos los archivos han sido procesados.")
	} else {
		// Procesar un solo archivo con interacción
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

		// Usar spinner para la animación de cargando
		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // CharSet 9 es "/-\|"
		s.Prefix = "Parseando fechas del vex "
		s.Start()

		err := processFile(inputFile, outputFile)
		if err != nil {
			s.Stop()
			fmt.Fprintf(os.Stderr, "\n%s\n", err)
			os.Exit(1)
		}

		s.Stop()
	}
}

