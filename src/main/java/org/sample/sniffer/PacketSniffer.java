package org.sample.sniffer;

import java.io.IOException;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsRDataPtr;
import org.pcap4j.packet.DnsPacket.DnsHeader;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.util.NifSelector;
import org.sample.sniffer.model.DNSEntry;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PacketSniffer {

	private static final Logger LOGGER = LogManager.getLogger(PacketSniffer.class);
	private static final Logger DNSPTR_LOGGER = LogManager.getLogger("DomainPTR");

	public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException {
		SpringApplication.run(PacketSniffer.class, args);

		LOGGER.info("Packet sniffer");

		PcapNetworkInterface device = getNetworkDevice();
		DNSPTR_LOGGER.info("Network interface: {}", device);

		if (device == null) {
			LOGGER.info("No interface selected");
			System.exit(1);
		}

		int snapshotLength = 65536;
		int readTimeout = 60;

		try (PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout)) {

			// filter DNS packets
			handle.setFilter("proto 17", BpfCompileMode.OPTIMIZE);
			handle.setFilter("udp port 53", BpfCompileMode.OPTIMIZE);

			HashMap<Short, DNSEntry> packets = new HashMap<>();

			PacketListener listener = packet -> {
				LOGGER.info("Captured at: {}", handle.getTimestamp());
				LOGGER.info(packet);

				DnsHeader dnsHeader = packet.get(DnsPacket.class).getHeader();
				if (!dnsHeader.isResponse()) {
					dnsHeader.getQuestions().forEach(q -> {
						if (q.getQType().equals(DnsResourceRecordType.PTR)) {
							packets.put(dnsHeader.getId(),
									new DNSEntry(dnsHeader.getId(), dnsHeader, q.getQName(), handle.getTimestamp()));
							return;
						}
					});
				} else {
					if (packets.containsKey(dnsHeader.getId())) {
						DNSEntry entry = packets.get(dnsHeader.getId());
						long diff = handle.getTimestamp().getTime() - entry.getQueryTimestamp().getTime();

						DNSPTR_LOGGER.info("------------------------");
						DNSPTR_LOGGER.info("Domain Name Pointer: {}", entry.getqName().getName());
						dnsHeader.getAnswers().forEach(a -> 
							DNSPTR_LOGGER.info("TTL:  {} & Pointer Name: {}", a.getTtl(), ((DnsRDataPtr) a.getRData()).getPtrDName().getName())
						);
						DNSPTR_LOGGER.info("Query timestamp: {} & Response timestamp: {}", entry.getQueryTimestamp(),
								handle.getTimestamp());
						DNSPTR_LOGGER.info("Time difference: {}", diff);
						DNSPTR_LOGGER.info("------------------------");

						packets.remove(dnsHeader.getId());
					}
				}
			};

			handle.loop(-1, listener);
		}
	}

	private static PcapNetworkInterface getNetworkDevice() {
		PcapNetworkInterface device = null;
		try {
			device = new NifSelector().selectNetworkInterface();
		} catch (IOException e) {
			LOGGER.error(e);
		}
		return device;
	}

}
