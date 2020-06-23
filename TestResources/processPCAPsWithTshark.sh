

for f in ./*.pcap; do
    # do some stuff here with "$f"
    # remember to quote it or spaces may misbehave
    tshark -r "$f" -T fields -E header=y -e frame.number -e eth.dst -e eth.src -e eth.type -e ip.version -e ip.hdr_len -e ip.dsfield.dscp -e ip.dsfield.ecn -e ip.len -e ip.id -e ip.flags.rb -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.hdr_len -e tcp.flags.res -e tcp.flags.ns -e tcp.flags.cwr -e tcp.flags.ecn -e tcp.flags.urg -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.fin -e tcp.window_size_value -e tcp.checksum -e tcp.urgent_pointer -e tcp.options -e tcp.payload -e udp.srcport -e udp.dstport -e udp.length -e udp.checksum > "$f".txt
done
