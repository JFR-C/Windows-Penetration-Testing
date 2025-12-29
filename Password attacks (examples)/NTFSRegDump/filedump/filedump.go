package filedump

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"github.com/t9t/gomft/mft"
	"fmt"
	"os"
	"syscall"
	"unicode/utf16"
	"log"
)

const (
	mftRecordSize  = 1024
	bootSectorSize = 512

	ATTR_TYPE_FILE_NAME = 0x30 // File name attribute
	ATTR_TYPE_DATA      = 0x80 // Data attribute
)

type BootSector struct {
	Jump                 [3]byte
	OEMID                [8]byte
	BytesPerSector       uint16
	SectorsPerCluster    uint8
	ReservedSectors      uint16
	Unused1              [3]byte
	Unused2              [2]byte
	MediaDescriptor      uint8
	Unused3              [2]byte
	SectorsPerTrack      uint16
	NumberOfHeads        uint16
	HiddenSectors        uint32
	Unused4              [8]byte
	TotalSectors         uint64
	MFTClusterNumber     uint64
	MFTMirrorCluster     uint64
	ClustersPerFileRecord int8
	ClustersPerIndexBuffer int8
	VolumeSerialNumber   [8]byte
	Checksum             uint32
}

func FindSystemVolume() string {
	volumeName := make([]uint16, windows.MAX_PATH+1)
	handle, err := windows.FindFirstVolume(&volumeName[0], uint32(len(volumeName)))
	if err != nil {
		log.Printf("Error finding first volume: %v\n", err)
	}
	defer windows.FindVolumeClose(handle)

	for {
		volumePath := syscall.UTF16ToString(volumeName)
		trimmedPath := trimVolumePath(volumePath)
		if checkWindowsDirectory(trimmedPath) {
			return trimmedPath
		}

		err = windows.FindNextVolume(handle, &volumeName[0], uint32(len(volumeName)))
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			log.Printf("Error finding next volume: %v\n", err)
		}
	}
	return ""
}

func trimVolumePath(volumePath string) string {
	// Trims the trailing backslash from the volume path, if present. This ensures uniform handling of paths.
	if len(volumePath) > 0 && volumePath[len(volumePath)-1] == '\\' {
		return volumePath[:len(volumePath)-1]
	}
	return volumePath
}

func checkWindowsDirectory(volumePath string) bool {
	windowsDirPath := volumePath + `\Windows`
	handle, err := windows.CreateFile(
		syscall.StringToUTF16Ptr(windowsDirPath),
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		log.Printf("Volume %s isn't the system volume, keep processing \n", volumePath)
		return false
	}
	defer windows.CloseHandle(handle)

	log.Printf("Volume %s contains the Windows directory.\n", volumePath)
	return true
}

func ExtractSystemFiles(volumePath string, targetFiles map[string]string) {
	for targetFile, outputFile := range targetFiles {
		extractFileFromVolume(volumePath, targetFile, outputFile)
	}
}

// Extracts a specific file from the given volume by reading the Master File Table (MFT) and saving the target file data to an output file.
func extractFileFromVolume(volumePath, targetFileName, outputFileName string) {
	file, err := os.Open(volumePath)
	if err != nil {
		log.Printf("Failed to open volume: %v\n", err)
	}
	defer file.Close()

	bootSector := BootSector{}
	if err := readBootSector(file, &bootSector); err != nil {
		log.Printf("Failed to read boot sector: %v\n", err)
	}

	mftStartOffset := calculateMFTOffset(&bootSector)
	log.Printf("MFT starts at byte offset: %d\n", mftStartOffset)

	if _, err = file.Seek(mftStartOffset, 0); err != nil {
		log.Printf("Failed to seek to MFT start: %v\n", err)
	}

	log.Printf("Starting to parse MFT records...")
	parseMFTRecords(file, &bootSector, targetFileName, outputFileName)
}

func readBootSector(file *os.File, bootSector *BootSector) error {
	buffer := make([]byte, bootSectorSize)
	if _, err := file.Read(buffer); err != nil {
		return fmt.Errorf("failed to read boot sector: %v", err)
	}

	reader := bytes.NewReader(buffer)
	if err := binary.Read(reader, binary.LittleEndian, bootSector); err != nil {
		return fmt.Errorf("failed to parse boot sector: %v", err)
	}
	return nil
}

func calculateMFTOffset(bootSector *BootSector) int64 {
	return int64(bootSector.MFTClusterNumber) * int64(bootSector.SectorsPerCluster) * int64(bootSector.BytesPerSector)
}

func parseMFTRecords(file *os.File, bootSector *BootSector, targetFileName, outputFileName string) {
	buffer := make([]byte, mftRecordSize)

	for recordIndex := 0; ; recordIndex++ {
		if _, err := file.Read(buffer); err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Printf("Error reading volume: %v\n", err)
		}

		record, err := mft.ParseRecord(buffer)
		if err != nil {
			continue
		}

		if found, data := findAndExtractTargetFile(&record, targetFileName, file, bootSector); found {
			if err := os.WriteFile(outputFileName, data, 0644); err != nil {
				log.Printf("Failed to write %s to disk: %v\n", targetFileName, err)
			}
			log.Printf("%s file saved to %s\n", targetFileName, outputFileName)
			return
		}
	}

	log.Printf("Failed to locate %s file in MFT records.\n", targetFileName)
}

func findAndExtractTargetFile(record *mft.Record, targetFileName string, file *os.File, bootSector *BootSector) (bool, []byte) {
	// Searches within an MFT record for the target file name and extracts the file data if found.
	for _, attr := range record.Attributes {
		if attr.Type == ATTR_TYPE_FILE_NAME {
			fileName := parseFileNameAttribute(attr.Data)
			if fileName == targetFileName {
				log.Printf("Found %s in MFT record\n", targetFileName)
				data, err := extractFileData(record, file, bootSector)
				if err != nil {
					log.Printf("Failed to extract %s data...\n", targetFileName)
					return false, nil
				}
				return true, data
			}
		}
	}
	return false, nil
}

// Parses the file name attribute from the raw attribute data and returns it as a string.
func parseFileNameAttribute(data []byte) string {
	if len(data) < 66 {
		return ""
	}

	nameLength := int(data[64])
	nameOffset := 66
	if len(data) < nameOffset+nameLength*2 {
		return ""
	}

	nameBytes := data[nameOffset : nameOffset+nameLength*2]
	nameUTF16 := make([]uint16, nameLength)
	if err := binary.Read(bytes.NewReader(nameBytes), binary.LittleEndian, &nameUTF16); err != nil {
		return ""
	}

	return string(utf16.Decode(nameUTF16))
}

// Extracts file data from an MFT record, handling both resident and non-resident data. Returns the extracted data or an error if extraction fails.
func extractFileData(record *mft.Record, file *os.File, bootSector *BootSector) ([]byte, error) {
	var data []byte

	for _, attr := range record.Attributes {
		if attr.Type == ATTR_TYPE_DATA {
			if attr.Resident {
				data = append(data, attr.Data...)
			} else {
				bytesPerCluster := int64(bootSector.BytesPerSector) * int64(bootSector.SectorsPerCluster)
				runList := attr.Data
				offset := int64(0)

				for len(runList) > 0 {
					header := runList[0]
					if header == 0 {
						break
					}

					runLengthSize := header & 0x0F
					runOffsetSize := (header >> 4) & 0x0F

					if len(runList) < 1+int(runLengthSize)+int(runOffsetSize) {
						return nil, fmt.Errorf("invalid run list, too short")
					}

					runLength := parseRunLength(runList[1 : 1+runLengthSize])
					runOffset := parseRunOffset(runList[1+runLengthSize : 1+runLengthSize+runOffsetSize])

					offset += runOffset
					clusterOffset := offset * bytesPerCluster
					clusterLength := runLength * bytesPerCluster

					if _, err := file.Seek(clusterOffset, 0); err != nil {
						return nil, fmt.Errorf("failed to seek to data run offset: %v", err)
					}

					clusterData := make([]byte, clusterLength)
					if _, err := file.Read(clusterData); err != nil {
						return nil, fmt.Errorf("failed to read data run: %v", err)
					}

					data = append(data, clusterData...)
					runList = runList[1+runLengthSize+runOffsetSize:]
				}
			}
		}
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data found in attribute")
	}

	return data, nil
}

// Parses the run length from the run list data, which indicates how many clusters are used.
func parseRunLength(runLengthData []byte) int64 {
	var runLength int64
	for i := 0; i < len(runLengthData); i++ {
		runLength |= int64(runLengthData[i]) << (8 * i)
	}
	return runLength
}

// Parses the run offset from the run list data, which indicates the relative location of the clusters.
func parseRunOffset(runOffsetData []byte) int64 {
	var runOffset int64
	for i := 0; i < len(runOffsetData); i++ {
		runOffset |= int64(runOffsetData[i]) << (8 * i)
	}
	if len(runOffsetData) > 0 && (runOffsetData[len(runOffsetData)-1]&0x80) > 0 {
		runOffset -= 1 << (len(runOffsetData) * 8)
	}
	return runOffset
}
