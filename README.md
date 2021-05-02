# Packet Sniffer

A TCP/UDP Packet Sniffer Tool implemented using [Pcap4J](https://github.com/kaitoy/pcap4j).

[:construction: Dev-in-progress]

## Build & Run

### Build

Execute the following command to build the project

> Use the `maven-wrapper` command if `maven` is not installed in your environment

```sh
mvn clean package

# maven wrapper command
./mvnw clean package
```

### Run

> Required `libcap` or `winpcap` (for Windows environment) libraries to capture packets. Please follow [Pcap4J Docs](https://www.pcap4j.org/) to install the native libraries in your environment prior to executing the JAR

```sh
java -jar target/packet-sniffer.jar
```

## License

[MIT](LICENSE)
