// Long term TODO: Calculation of RTT is not correct. Should use previous ACK...

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gonum.org/v1/gonum/floats"
	"gonum.org/v1/gonum/stat"
)

func floatToString(inputNum float64) string {
	// to convert a float number to a string
	return strconv.FormatFloat(inputNum, 'f', -1, 64)
}

func writeFullArray(resultsArray []map[string]float64, key flowKey, fileName string) {
	records := make([][]string, 0, len(resultsArray)+1)
	records = append(records, []string{"window", "rtt", "ackTimestamp", "dataTimestamp", "loss"})
	for _, v := range resultsArray {
		records = append(records, []string{floatToString(v["window"]), floatToString(v["rtt"]), floatToString(v["ackTimestamp"]), floatToString(v["dataTimestamp"]), floatToString(v["loss"])})
	}

	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalln("Couldn't open file for writing", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)

	for _, record := range records {
		if err := w.Write(record); err != nil {
			log.Fatalln("error writing record to csv:", err)
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
}

func writeMinimalArray(resultsArray []map[string]float64, key flowKey, fileName string) {

	windows := make([]float64, 0, len(resultsArray))
	rtts := make([]float64, 0, len(resultsArray))
	ackTimestamps := make([]float64, 0, len(resultsArray))
	// dataTimestamps := make([]float64, 0, len(resultsArray))
	losses := make([]float64, 0, len(resultsArray))
	bytes := make([]float64, 0, len(resultsArray))

	for _, v := range resultsArray {
		windows = append(windows, v["window"])
		rtts = append(rtts, v["rtt"])
		ackTimestamps = append(ackTimestamps, v["ackTimestamp"])
		// dataTimestamps = append(dataTimestamps, v["dataTimestamp"])
		losses = append(losses, v["lossBytes"])
		bytes = append(bytes, v["bytes"])
	}

	indices := getIndicesAtRtt(ackTimestamps, rtts)
	selectedAckTimes := selectIndices(indices, ackTimestamps)
	selectedAckTimes = selectedAckTimes[:len(selectedAckTimes)-1]
	averagedWindows := getAverageOverIndices(indices, windows)
	// averagedWindows := getMaxOverIndices(indices, windows)
	averagedRtts := getAverageOverIndices(indices, rtts)
	// averagedLosses := getAverageOverIndices(indices, losses)
	summedLosses := getSumOverIndices(indices, losses)
	summedBytes := getSumOverIndices(indices, bytes)

	// if !(len(selectedAckTimes) == len(averagedWindows) && len(averagedWindows) == len(averagedRtts) && len(averagedWindows) == len(averagedLosses)) {
	// 	log.Fatalf("ackTimestamps: %d, averagedWindows: %d, averagedRtts: %d, averagedLosses: %d\n", len(selectedAckTimes), len(averagedWindows), len(averagedRtts), len(averagedLosses))
	// }

	records := make([][]string, 0, len(averagedWindows)+1)
	records = append(records, []string{"ackTimestamp", "window", "rtt", "loss", "bytes"})
	for i := range selectedAckTimes {
		records = append(records, []string{floatToString(selectedAckTimes[i]), floatToString(averagedWindows[i]), floatToString(averagedRtts[i]), floatToString(summedLosses[i]), floatToString(summedBytes[i])})
	}

	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalln("Couldn't open file for writing", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)

	for _, record := range records {
		if err := w.Write(record); err != nil {
			log.Fatalln("error writing record to csv:", err)
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	// fmt.Println(os.Args[1])
	flows := extractFlowsFromPcap(os.Args[1])
	// for k, v := range flows {
	// 	fmt.Printf("key[%s] value[%d]\n", k, len(v))
	// }
	keys := make([]flowKey, 0, len(flows))
	for k := range flows {
		// fmt.Println(k)
		keys = append(keys, k)
	}
	for _, k := range keys {
		fmt.Println(k)
	}
	if len(keys) != 1 {
		log.Fatalf("Shouldn't have more than one key but has %d.\n", len(keys))
	}
	srcIP := net.IP([]byte(keys[0].ip1))
	dstIP := net.IP([]byte(keys[0].ip2))
	srcPort := keys[0].port1
	dstPort := keys[0].port2
	resultsArray := parsePackets(flows[keys[0]], srcIP, dstIP, srcPort, dstPort)
	resultsArrayOtherWay := parsePackets(flows[keys[0]], dstIP, srcIP, dstPort, srcPort)

	if len(resultsArray) <= 0 {
		log.Println("Got empty results array!")
		// os.Exit(-389)
	}
	fmt.Printf("results len: %d\n", len(resultsArray))

	if len(resultsArrayOtherWay) <= 0 {
		log.Println("Got empty resultsOtherWay array!")
		// os.Exit(-389)
	}
	fmt.Printf("resultsOtherWay len: %d\n", len(resultsArrayOtherWay))

	if len(resultsArray) > 1 {
		writeFullArray(resultsArray, keys[0], os.Args[1][:len(os.Args[1])-5]+"_full_1.csv")
		writeMinimalArray(resultsArray, keys[0], os.Args[1][:len(os.Args[1])-5]+"_1.csv")
	}
	if len(resultsArrayOtherWay) > 1 {
		writeFullArray(resultsArrayOtherWay, keys[0], os.Args[1][:len(os.Args[1])-5]+"_full_2.csv")
		writeMinimalArray(resultsArrayOtherWay, keys[0], os.Args[1][:len(os.Args[1])-5]+"_2.csv")
	}

	os.Exit(0)
}

type flowKey struct {
	ip1   string
	ip2   string
	port1 uint16
	port2 uint16
}

func (key flowKey) String() string {
	return fmt.Sprintf("%s, %s, %d, %d", net.IP([]byte(key.ip1)), net.IP([]byte(key.ip2)), key.port1, key.port2)
}

type packetAndCi struct {
	packet *gopacket.Packet
	ci     *gopacket.CaptureInfo
}

// min returns the smaller of x or y.
func minU64(x, y uint64) uint64 {
	if x > y {
		return y
	}
	return x
}

// max returns the larger of x or y.
func maxU64(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}

// min returns the smaller of x or y.
func minU32(x, y uint32) uint32 {
	if x > y {
		return y
	}
	return x
}

// max returns the larger of x or y.
func maxU32(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}

// min returns the smaller of x or y.
func minU16(x, y uint16) uint16 {
	if x > y {
		return y
	}
	return x
}

// max returns the larger of x or y.
func maxU16(x, y uint16) uint16 {
	if x < y {
		return y
	}
	return x
}

// func ip2Int(ip []byte) uint32 {
// 	return binary.BigEndian.Uint32(ip)
// }

// func int2Ip(ipInt uint32) []byte {
// 	ipByte := make([]byte, 4)
// 	binary.BigEndian.PutUint32(ipByte, ipInt)
// 	return ipByte
// }

func extractFlowsFromPcap(pcapPath string) map[flowKey][]packetAndCi {
	flows := make(map[flowKey][]packetAndCi)

	// fmt.Println("Opening pcap")
	packets, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}

	var counter uint64 = 0
	for {
		data, ci, err := packets.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} else {
			p := gopacket.NewPacket(data, packets.LinkType(), gopacket.Lazy)

			pTCP, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)

			if !ok {
				// log.Fatal("Decoding TCP failed")
				continue
			}

			pIP4, ok4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			pIP6, ok6 := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

			if !ok4 && !ok6 {
				panic("First IP failed")
			}

			var src net.IP
			var dst net.IP
			// src, dst := ip2Int(pIP.SrcIP), ip2Int(pIP.DstIP)
			if ok4 {
				src, dst = pIP4.SrcIP, pIP4.DstIP
			} else {
				src, dst = pIP6.SrcIP, pIP6.DstIP
			}
			sport, dport := uint16(pTCP.SrcPort), uint16(pTCP.DstPort)

			if sport == 0 && dport == 0 {
				// fmt.Printf("%d: sport and dport are zero!\n", counter)
				continue
			}

			var minIP net.IP
			var maxIP net.IP
			var minPort uint16
			var maxPort uint16
			if bytes.Compare(src, dst) < 0 {
				minIP = src
				maxIP = dst
				minPort = sport
				maxPort = dport
			} else if bytes.Compare(src, dst) > 0 {
				minIP = dst
				maxIP = src
				minPort = dport
				maxPort = sport
			} else {
				minIP = dst
				maxIP = src
				minPort = minU16(sport, dport)
				maxPort = maxU16(sport, dport)
			}
			flowTuple := flowKey{string(minIP), string(maxIP), minPort, maxPort}

			if _, ok := flows[flowTuple]; ok {
				flows[flowTuple] = append(flows[flowTuple], packetAndCi{&p, &ci})
			} else {
				flows[flowTuple] = []packetAndCi{}
				flows[flowTuple] = append(flows[flowTuple], packetAndCi{&p, &ci})
			}
		}
		counter++
	}
	return flows
}

func getTimestamps(optionsArray []layers.TCPOption) (uint32, uint32, bool) {
	for _, t := range optionsArray {
		if t.OptionType == layers.TCPOptionKindTimestamps && len(t.OptionData) == 8 {
			return binary.BigEndian.Uint32(t.OptionData[:4]), binary.BigEndian.Uint32(t.OptionData[4:8]), true
		}
	}
	return 0, 0, false
}

func getMss(optionsArray []layers.TCPOption) (uint32, bool) {
	for _, t := range optionsArray {
		if t.OptionType == layers.TCPOptionKindMSS && len(t.OptionData) == 2 {
			return uint32(binary.BigEndian.Uint16(t.OptionData[0:2])), true
		}
	}
	return 0, false
}

func findCorrespondingDataSegment(originalIndex uint64, tsVal uint32, packets []packetAndCi, srcIP []byte, dstIP []byte, srcPort uint16, dstPort uint16, ok4 bool, actualSeq int64) (uint64, *gopacket.Packet, bool) {
	for i := int(originalIndex) + 1; i < len(packets); i++ {
		currentPacketAndCi := packets[i]
		p := currentPacketAndCi.packet
		pTCP, ok := (*p).Layer(layers.LayerTypeTCP).(*layers.TCP)

		if !ok {
			panic("findCorrespondingDataSegment: TCP not ok")
		}

		if ok4 {
			var pIP *layers.IPv4
			pIP, ok = (*p).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !(bytes.Equal(pIP.SrcIP, srcIP) && bytes.Equal(pIP.DstIP, dstIP) && uint16(pTCP.SrcPort) == srcPort && uint16(pTCP.DstPort) == dstPort) {
				continue
			}
		} else {
			var pIP *layers.IPv6
			pIP, ok = (*p).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !(bytes.Equal(pIP.SrcIP, srcIP) && bytes.Equal(pIP.DstIP, dstIP) && uint16(pTCP.SrcPort) == srcPort && uint16(pTCP.DstPort) == dstPort) {
				continue
			}
		}
		_, tsEcr, ok := getTimestamps(pTCP.Options)

		if !ok {
			log.Printf("findCorrespondingDataSegment: Timestamps broken\n")
			continue
		} else if tsEcr == tsVal && isGreaterThanLastSeq(pTCP.Seq, actualSeq) {
			return uint64(i), p, true
		} else if tsEcr > tsVal {
			return 0, nil, false
		}
	}
	return 0, nil, false
}

func findCorrespondingAck(originalIndex uint64, seqNum uint32, tsVal uint32, packets []packetAndCi, srcIP []byte, dstIP []byte, srcPort uint16, dstPort uint16, ok4 bool) (uint64, *gopacket.Packet, bool) {
	for i := int(originalIndex) + 1; i < len(packets); i++ {
		currentPacketAndCi := packets[i]
		p := currentPacketAndCi.packet
		pTCP, ok := (*p).Layer(layers.LayerTypeTCP).(*layers.TCP)

		if !ok {
			panic("findCorrespondingAck: TCP not ok")
		}

		if ok4 {
			var pIP *layers.IPv4
			pIP, ok = (*p).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !(bytes.Equal(pIP.SrcIP, dstIP) && bytes.Equal(pIP.DstIP, srcIP) && uint16(pTCP.SrcPort) == dstPort && uint16(pTCP.DstPort) == srcPort) {
				continue
				// panic("Wrong IP address!")
			}
		} else {
			var pIP *layers.IPv6
			pIP, ok = (*p).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !(bytes.Equal(pIP.SrcIP, dstIP) && bytes.Equal(pIP.DstIP, srcIP) && uint16(pTCP.SrcPort) == dstPort && uint16(pTCP.DstPort) == srcPort) {
				// log.Printf("Failing here :(\n")
				continue
				// panic("Wrong IP address!")
			} else {
				// log.Printf("Continuing here :)\n")
			}
		}
		_, tsEcr, ok := getTimestamps(pTCP.Options)
		ack := pTCP.Ack

		if !ok {
			log.Printf("findCorrespondingAck: Timestamps broken\n")
			// } else if ack == seqNum && tsVal == tsEcr {
		} else if tsVal == tsEcr && ack == seqNum {
			// } else if tsVal == tsEcr {
			return uint64(i), p, true
		} else if tsVal < tsEcr || ack > seqNum { //|| ack > seqNum {
			// } else if tsVal > tsEcr {
			// log.Printf("tsVal: %d, tsEcr: %d, ack: %d, seqNum: %d, diff: %d\n", tsVal, tsEcr, ack, seqNum, int(ack)-int(seqNum))
			return 0, nil, false
		}
	}
	// panic("findCorrespondingAck: Shouldn't get here")
	return 0, nil, false
}

func isGreaterThanLastSeq(seqNumber uint32, lastSeq int64) bool {
	return int64(seqNumber) > lastSeq || (int64(seqNumber) < lastSeq && uint64(lastSeq) > (uint64(1)<<32)*3/4 && uint64(seqNumber) < (uint64(1)<<32)/4)
}

const tcpHeaderLength uint64 = 20
const ipv4HeaderLength uint64 = 20
const ipv6HeaderLength uint64 = 40

func parsePackets(packets []packetAndCi, srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) []map[string]float64 {
	// fmt.Printf("len: %d, src: %s, dst: %s\n", len(packets), srcIP, dstIP)
	fmt.Printf("Number of packets found: %d\n", len(packets))
	windowsAtTime := make([]map[string]float64, 0, (len(packets)))
	// sentTimeStamps := make([]uint64, 0, (len(packets)))
	// timesOfSentTimeStamps := make([]uint64, 0, (len(packets)))

	var lastSeq int64 = -1
	var lastDataSeq int64 = -1

	retransmissions := 0
	retransmissionBytes := 0
	dataBytes := 0
	dataPackets := 0
	minAckTimestamp := math.Inf(1)
	minDataTimestamp := math.Inf(1)
	minPacketTimestamp := math.Inf(1)

	okOnes := 0
	couldntFindAck := 0
	couldFindAck := 0
	couldntFindDataSegment := 0
	couldFindDataSegment := 0
	totalRetransmissions := 0

	var lastFoundAck uint64 = 0
	var lastFoundDataSegment uint64 = 0
	var maximumPacketSize uint64 = 0
	var mss uint64 = 0
	var minimumOptions uint64 = math.MaxUint64
	var maxLen uint64 = 0

	var globalOk4 bool
	// var globalOk6 bool

	for index, pc := range packets {
		p, ci := pc.packet, pc.ci

		pTCP, ok := (*p).Layer(layers.LayerTypeTCP).(*layers.TCP)

		if !ok {
			// log.Println("First TCP failed")
			panic("First TCP failed")
		}

		pIP4, ok4 := (*p).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		pIP6, ok6 := (*p).Layer(layers.LayerTypeIPv6).(*layers.IPv6)

		if !ok4 && !ok6 {
			panic("First IP failed")
		}

		// var pIP interface{}
		// if ok4 {
		// 	pIP := pIP4
		// } else {
		// 	pIP := pIP6
		// }

		if ok4 {
			if !(bytes.Equal(pIP4.SrcIP, srcIP) && bytes.Equal(pIP4.DstIP, dstIP) && uint16(pTCP.SrcPort) == srcPort && uint16(pTCP.DstPort) == dstPort) {
				// fmt.Printf("%s, %s; %s, %s, %t\n", pIP.SrcIP, pIP.DstIP, srcIP, dstIP, ok)
				// log.Println("Wrong direction")
				continue
			}
		} else {
			if !(bytes.Equal(pIP6.SrcIP, srcIP) && bytes.Equal(pIP6.DstIP, dstIP) && uint16(pTCP.SrcPort) == srcPort && uint16(pTCP.DstPort) == dstPort) {
				// fmt.Printf("%s, %s; %s, %s, %t\n", pIP.SrcIP, pIP.DstIP, srcIP, dstIP, ok)
				// log.Println("Wrong direction")
				continue
			}
		}

		pOpts := pTCP.Options
		mssReturned, ok := getMss(pOpts)
		if ok {
			mss = uint64(mssReturned)
		}
		// var maxLen uint64 = 0
		if ok4 {
			maxLen = maxU64(maxLen, uint64(pIP4.Length))
			globalOk4 = true
		} else {
			maxLen = maxU64(maxLen, uint64(pIP6.Length)+ipv6HeaderLength)
			// globalOk6 = true
		}

		if !pTCP.SYN {
			minimumOptions = minU64(uint64(pTCP.DataOffset)*4-20, minimumOptions)
		}

		tsVal, _, ok := getTimestamps(pOpts)

		if !ok {
			// log.Println("Timestamps not ok")
			log.Printf("Timestamps not ok\n")
		}

		if !isGreaterThanLastSeq(pTCP.Seq, lastSeq) {
			// log.Println("Retransmission")
			if ok4 {
				retransmissionBytes += int(uint32(pIP4.Length) - uint32(pIP4.IHL)*4 - uint32(pTCP.DataOffset)*4)
			} else {
				retransmissionBytes += int(uint32(pIP6.Length) - uint32(pTCP.DataOffset)*4)
			}
			retransmissions++
			totalRetransmissions++
			continue
		}
		dataPackets++
		if ok4 {
			dataBytes += int(uint32(pIP4.Length) - uint32(pIP4.IHL)*4 - uint32(pTCP.DataOffset)*4)
		} else {
			dataBytes += int(uint32(pIP6.Length) - uint32(pTCP.DataOffset)*4)
		}
		lastSeq = int64(pTCP.Seq)
		var ackIndex uint64
		var ackPacket *gopacket.Packet
		if ok4 {
			ackIndex, ackPacket, ok = findCorrespondingAck(maxU64(uint64(index), lastFoundAck), uint32(lastSeq+int64(pIP4.Length-uint16(pIP4.IHL)*4-uint16(pTCP.DataOffset)*4)), tsVal, packets, srcIP, dstIP, srcPort, dstPort, ok4)
		} else {
			ackIndex, ackPacket, ok = findCorrespondingAck(maxU64(uint64(index), lastFoundAck), uint32(lastSeq+int64(pIP6.Length-uint16(pTCP.DataOffset)*4)), tsVal, packets, srcIP, dstIP, srcPort, dstPort, ok4)
		}
		lastFoundAck = ackIndex
		if ok4 {
			maximumPacketSize = maxU64(uint64(pIP4.Length), maximumPacketSize)
		} else {
			maximumPacketSize = maxU64(uint64(pIP6.Length)+ipv6HeaderLength, maximumPacketSize)
		}

		if !ok {
			// log.Printf("Didn't ack\n")
			couldntFindAck++
			// log.Printf("Ack packet not ok, payload length %d from TCP, payload length from %d from IP\n", len(pTCP.Payload), pIP.Length-uint16(pIP.IHL)*4-uint16(pTCP.DataOffset)*4)
			continue
		} else {
			couldFindAck++
			// log.Printf("Found ack\n")
		}

		ackTCP, ok := (*ackPacket).Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			// log.Println("Parsing ack TCP failed")
			panic("Parsing ack TCP failed")
		}
		ackOpts := ackTCP.Options

		ackTsVal, _, ok := getTimestamps(ackOpts)

		dataIndex, dataPacket, ok := findCorrespondingDataSegment(maxU64(uint64(ackIndex), lastFoundDataSegment), ackTsVal, packets, srcIP, dstIP, srcPort, dstPort, ok4, lastDataSeq)
		lastFoundDataSegment = dataIndex

		// log.Printf("Survived 5\n")

		if !ok {
			couldntFindDataSegment++
			// log.Println("Data packet not ok")
			continue
		} else {
			couldFindDataSegment++
		}

		// log.Printf("Survived 4\n")

		var dataIP4 *layers.IPv4
		var dataIP6 *layers.IPv6
		if ok4 {
			dataIP4, ok = (*dataPacket).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		} else {
			dataIP6, ok = (*dataPacket).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		}
		if !ok {
			// log.Println("Parsing data IP failed")
			panic("Parsing data IP failed")
		}

		dataTCP, ok := (*dataPacket).Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			// log.Println("Parsing data TCP failed")
			panic("Parsing data TCP failed")
		}

		// log.Printf("Survived 3\n")

		actualSeq := uint64(dataTCP.Seq)
		lastDataSeq = int64(actualSeq)

		if ok4 {
			if dataTCP.Seq+uint32(dataIP4.Length-uint16(dataIP4.IHL)*4-uint16(dataTCP.DataOffset)*4) < ackTCP.Ack {
				actualSeq = actualSeq + (uint64(1) << 32)
			}
		} else {
			if dataTCP.Seq+uint32(dataIP6.Length-uint16(dataTCP.DataOffset)*4) < ackTCP.Ack {
				actualSeq = actualSeq + (uint64(1) << 32)
			}
		}

		var window uint64
		// window := actualSeq + uint64(dataIP.Length) - uint64(dataIP.IHL)*4 - uint64(dataTCP.DataOffset)*4 - uint64(ackTCP.Ack)
		// log.Printf("Survived 2\n")

		if ok4 {
			window = actualSeq + uint64(dataIP4.Length) - uint64(dataIP4.IHL)*4 - tcpHeaderLength - uint64(ackTCP.Ack) + 1
		} else {
			window = actualSeq + uint64(dataIP6.Length) - tcpHeaderLength - uint64(ackTCP.Ack) + 1
		}

		// log.Printf("Survived 1\n")

		// window := actualSeq + uint64(len(dataTCP.Payload)) - uint64(ackTCP.Ack)

		rtt := float64(packets[dataIndex].ci.Timestamp.Sub(ci.Timestamp).Nanoseconds()) / float64(time.Second.Nanoseconds())

		ackTimestamp := float64(packets[ackIndex].ci.Timestamp.UnixNano()) / float64(time.Second.Nanoseconds())
		minAckTimestamp = math.Min(minAckTimestamp, ackTimestamp)
		dataTimestamp := float64(packets[dataIndex].ci.Timestamp.UnixNano()) / float64(time.Second.Nanoseconds())
		minDataTimestamp = math.Min(minDataTimestamp, dataTimestamp)
		packetTimestamp := float64(ci.Timestamp.UnixNano()) / float64(time.Second.Nanoseconds())
		minPacketTimestamp = math.Min(minPacketTimestamp, packetTimestamp)

		// returnMap := map[string]float64{"window": float64(window), "rtt": rtt, "ackTimestamp": ackTimestamp - minAckTimestamp, "dataTimestamp": dataTimestamp - minDataTimestamp, "loss": float64(retransmissions), "loss_bytes": float64(retransmissionBytes), "packets": float64(dataPackets), "bytes": float64(dataBytes)}
		// returnMap := map[string]float64{"window": float64(window), "rtt": rtt, "ackTimestamp": ackTimestamp - minAckTimestamp, "dataTimestamp": dataTimestamp - minDataTimestamp, "lossBytes": float64(retransmissionBytes), "bytes": float64(dataBytes)}
		// returnMap := map[string]float64{"window": float64(window), "rtt": rtt, "ackTimestamp": packetTimestamp - minPacketTimestamp, "lossBytes": float64(retransmissionBytes), "bytes": float64(dataBytes)}
		// returnMap := map[string]float64{"window": float64(window), "rtt": rtt, "ackTimestamp": ackTimestamp - minAckTimestamp, "lossBytes": float64(retransmissionBytes), "bytes": float64(dataBytes)}
		returnMap := map[string]float64{"window": float64(window), "rtt": rtt, "ackTimestamp": ackTimestamp - minAckTimestamp, "lossBytes": float64(retransmissionBytes), "bytes": float64(dataBytes)}

		windowsAtTime = append(windowsAtTime, returnMap)
		retransmissions = 0
		retransmissionBytes = 0
		dataPackets = 0
		dataBytes = 0
		okOnes++
	}

	fmt.Printf("MaxLen: %d, MSS: %d, minimumOptions: %d\n", maxLen, mss, minimumOptions)

	payloadLength := maxLen - tcpHeaderLength - minimumOptions
	if globalOk4 {
		payloadLength -= ipv4HeaderLength
	} else {
		payloadLength -= ipv6HeaderLength
	}

	windowsAtTime2 := make([]map[string]float64, 0, (len(windowsAtTime)))
	for _, item := range windowsAtTime {
		returnMap2 := map[string]float64{"window": item["window"] / float64(payloadLength), "rtt": item["rtt"], "ackTimestamp": item["ackTimestamp"], "lossBytes": item["lossBytes"] / float64(payloadLength), "bytes": item["bytes"] / float64(payloadLength)}
		windowsAtTime2 = append(windowsAtTime2, returnMap2)
	}
	fmt.Printf("ratio of ok ones: %f, couldntFindAck: %f, couldntFindDataSegment: %f, totalRetransmissions: %f, didntFindAck: %f, didntFindData: %f\n", float64(okOnes)/float64(len(packets)), float64(couldntFindAck)/float64(len(packets)), float64(couldntFindDataSegment)/float64(len(packets)), float64(totalRetransmissions)/float64(len(packets)), float64(couldntFindAck)/float64(couldntFindAck+couldFindAck), float64(couldntFindDataSegment)/float64(couldntFindDataSegment+couldFindDataSegment))
	return windowsAtTime2
}

func getIndicesAtRtt(times []float64, rtts []float64) []uint64 {
	returnValues := make([]uint64, 0)
	nextTime := math.Inf(-1)
	for i, time := range times {
		if time >= nextTime {
			returnValues = append(returnValues, uint64(i))
			nextTime = time + rtts[i]
		}
	}
	return returnValues
}

func getAverageOverIndices(indices []uint64, thingsToBeAveraged []float64) []float64 {
	averagedThings := make([]float64, 0, len(indices))
	for i, _ := range indices[:len(indices)-1] {
		averagedThings = append(averagedThings, stat.Mean(thingsToBeAveraged[indices[i]:indices[i+1]], nil))
	}
	return averagedThings
}

func getMaxOverIndices(indices []uint64, thingsToBeAveraged []float64) []float64 {
	averagedThings := make([]float64, 0, len(indices))
	for i, _ := range indices[:len(indices)-1] {
		averagedThings = append(averagedThings, floats.Max(thingsToBeAveraged[indices[i]:indices[i+1]]))
	}
	return averagedThings
}

func getSumOverIndices(indices []uint64, thingsToBeAveraged []float64) []float64 {
	averagedThings := make([]float64, 0, len(indices))
	for i, _ := range indices[:len(indices)-1] {
		averagedThings = append(averagedThings, float64(indices[i+1]-indices[i])*stat.Mean(thingsToBeAveraged[indices[i]:indices[i+1]], nil))
	}
	return averagedThings
}

func selectIndices(indices []uint64, thingsToBeSelected []float64) []float64 {
	returnValues := make([]float64, 0, len(indices))
	for _, index := range indices {
		returnValues = append(returnValues, thingsToBeSelected[index])
	}
	return returnValues
}
