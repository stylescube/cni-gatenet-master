#COMMON VARIABLES
SOURCE_IP=10.244.0.2
SOURCE_TUNNEL=10.0.0.2
DESTINATION_IP=10.240.0.5
DESTINATION_LOCAL=10.240.0.5
DESTINATION_TUNNEL=10.0.0.1
TUNNEL_NAME=tun1
TUNNEL_RANGE=30
TUNNEL_PORT=5454
TUNNEL_TTL=10
UMARK=7

#SOURCE POD
ip fou add port $TUNNEL_PORT gue #Add this
ip link add name $TUNNEL_NAME type ipip local $SOURCE_IP remote $DESTINATION_IP ttl $TUNNEL_TTL encap gue encap-sport $TUNNEL_PORT encap-dport $TUNNEL_PORT encap-csum
ip link set $TUNNEL_NAME up
ip addr add $SOURCE_TUNNEL/$TUNNEL_RANGE dev $TUNNEL_NAME
ip rule add fwmark 7 table 7
ip route add default via $DESTINATION_TUNNEL dev $TUNNEL_NAME table 7
iptables -t mangle -A OUTPUT -o eth0 -j MARK --set-mark 7

#GATE POD
ip fou add port $TUNNEL_PORT gue
ip link add name $TUNNEL_NAME type ipip local $DESTINATION_LOCAL remote $SOURCE_IP ttl $TUNNEL_TTL encap gue encap-sport $TUNNEL_PORT encap-dport $TUNNEL_PORT encap-csum
ip link set $TUNNEL_NAME up
ip addr add $DESTINATION_TUNNEL/$TUNNEL_RANGE dev $TUNNEL_NAME
ip rule add fwmark $UMARK table $UMARK
ip route add default via $DESTINATION_TUNNEL dev $TUNNEL_NAME table $UMARK
iptables -t mangle -A FORWARD -s $SOURCE_IP -j CONNMARK --set-mark $UMARK
iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#AN ALL WORKER NODES
modprobe ipip
modprobe fou