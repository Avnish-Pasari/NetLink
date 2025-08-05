#pragma once

#include "network_interface.hh"

#include <optional>
#include <queue>

// A wrapper for NetworkInterface that makes the host-side
// interface asynchronous: instead of returning received datagrams
// immediately (from the `recv_frame` method), it stores them for
// later retrieval. Otherwise, behaves identically to the underlying
// implementation of NetworkInterface.
class AsyncNetworkInterface : public NetworkInterface
{
  std::queue<InternetDatagram> datagrams_in_ {};

public:
  using NetworkInterface::NetworkInterface;

  // Construct from a NetworkInterface
  explicit AsyncNetworkInterface( NetworkInterface&& interface ) : NetworkInterface( interface ) {}

  // \brief Receives and Ethernet frame and responds appropriately.

  // - If type is IPv4, pushes to the `datagrams_out` queue for later retrieval by the owner.
  // - If type is ARP request, learn a mapping from the "sender" fields, and send an ARP reply.
  // - If type is ARP reply, learn a mapping from the "target" fields.
  //
  // \param[in] frame the incoming Ethernet frame
  void recv_frame( const EthernetFrame& frame )
  {
    auto optional_dgram = NetworkInterface::recv_frame( frame );
    if ( optional_dgram.has_value() ) {
      datagrams_in_.push( std::move( optional_dgram.value() ) );
    }
  };

  // Access queue of Internet datagrams that have been received
  std::optional<InternetDatagram> maybe_receive()
  {
    if ( datagrams_in_.empty() ) {
      return {};
    }

    InternetDatagram datagram = std::move( datagrams_in_.front() );
    datagrams_in_.pop();
    return datagram;
  }
};

// A router that has multiple network interfaces and
// performs longest-prefix-match routing between them.
class Router
{
  // The router's collection of network interfaces
  std::vector<AsyncNetworkInterface> interfaces_ {};

  // -- My Data structures --

  // Routing Table Entry
  struct RoutingTableEntry {
    // Route prefix
    uint32_t route_prefix;
    // Prefix length
    uint8_t prefix_length;
    // The IP address of the next hop. Will be empty if the network is directly attached to the router
    std::optional<Address> next_hop;
    // Interface number
    size_t interface_num;

    // Default constructor initializes members to safe defaults.
    RoutingTableEntry()
        : route_prefix(0),
          prefix_length(0),
          next_hop(std::nullopt),
          interface_num(0) { }
  };

  // Routing Table
  std::vector<RoutingTableEntry> RoutingTable;

public:

  // Default constructor for the Router class.
  Router();

  // Add an interface to the router
  // interface: an already-constructed network interface
  // returns the index of the interface after it has been added to the router
  size_t add_interface( AsyncNetworkInterface&& interface )
  {
    interfaces_.push_back( std::move( interface ) );
    return interfaces_.size() - 1;
  }

  // Access an interface by index
  AsyncNetworkInterface& interface( size_t N ) { return interfaces_.at( N ); }

  // Add a route (a forwarding rule)
  void add_route( uint32_t route_prefix,
                  uint8_t prefix_length,
                  std::optional<Address> next_hop,
                  size_t interface_num );

  // Route packets between the interfaces. For each interface, use the
  // maybe_receive() method to consume every incoming datagram and
  // send it on one of interfaces to the correct next hop. The router
  // chooses the outbound interface and next-hop as specified by the
  // route with the longest prefix_length that matches the datagram's
  // destination address.
  void route();

  // -- My Helper Functions --

  /***
   * Checks if there is a prefix match between two IP addresses
   * 
   * @param ip_address1 The first IP address
   * @param ip_address2 The second IP address
   * @param prefix_length The number of bits to match (0 to 32 inclusive)
   * 
   * @return true if there is a prefix match, false otherwise
   */
  bool isPrefixMatch(uint32_t ip_address1, uint32_t ip_address2, uint8_t prefix_length);
  
};
