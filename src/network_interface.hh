#pragma once

#include "address.hh"
#include "ethernet_frame.hh"
#include "ipv4_datagram.hh"
#include "arp_message.hh"

#include <iostream>
#include <list>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>


// A "network interface" that connects IP (the internet layer, or network layer)
// with Ethernet (the network access layer, or link layer).

// This module is the lowest layer of a TCP/IP stack
// (connecting IP with the lower-layer network protocol,
// e.g. Ethernet). But the same module is also used repeatedly
// as part of a router: a router generally has many network
// interfaces, and the router's job is to route Internet datagrams
// between the different interfaces.

// The network interface translates datagrams (coming from the
// "customer," e.g. a TCP/IP stack or router) into Ethernet
// frames. To fill in the Ethernet destination address, it looks up
// the Ethernet address of the next IP hop of each datagram, making
// requests with the [Address Resolution Protocol](\ref rfc::rfc826).
// In the opposite direction, the network interface accepts Ethernet
// frames, checks if they are intended for it, and if so, processes
// the the payload depending on its type. If it's an IPv4 datagram,
// the network interface passes it up the stack. If it's an ARP
// request or reply, the network interface processes the frame
// and learns or replies as necessary.
class NetworkInterface
{
private:
  // Ethernet (known as hardware, network-access, or link-layer) address of the interface
  EthernetAddress ethernet_address_;

  // IP (known as Internet-layer or network-layer) address of the interface
  Address ip_address_;

  // -- My Data structures --

  struct ARPTableEntry
  {
    // an entry is considered complete if it has both corresponding IP and MAC address
    bool complete_entry; // true if the entry is complete, false if it is incomplete

    uint32_t ip_address;
    EthernetAddress mac_address;
    int ttl; // time to live, in milliseconds

    // Default constructor initializes members to safe defaults.
    ARPTableEntry() 
      : complete_entry(false), ip_address(0), mac_address(), ttl(0) { }
  };

  struct IPQueue
  {
    uint32_t ip_address;
    std::vector<InternetDatagram> datagrams;

    // Initialize ip_address to 0 and datagrams as an empty vector.
    IPQueue() : ip_address(0), datagrams() { }
  };

  // ARP table
  std::vector<ARPTableEntry> ARPTable;
  // Ready-to-be-sent queue
  std::vector<EthernetFrame> ReadyToBeSentQueue;
  // List of IP queues
  std::vector<IPQueue> IPQueues;

public:
  // Construct a network interface with given Ethernet (network-access-layer) and IP (internet-layer)
  // addresses
  NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address );

  // Access queue of Ethernet frames awaiting transmission
  std::optional<EthernetFrame> maybe_send();

  // Sends an IPv4 datagram, encapsulated in an Ethernet frame (if it knows the Ethernet destination
  // address). Will need to use [ARP](\ref rfc::rfc826) to look up the Ethernet destination address
  // for the next hop.
  // ("Sending" is accomplished by making sure maybe_send() will release the frame when next called,
  // but please consider the frame sent as soon as it is generated.)
  void send_datagram( const InternetDatagram& dgram, const Address& next_hop );

  // Receives an Ethernet frame and responds appropriately.
  // If type is IPv4, returns the datagram.
  // If type is ARP request, learn a mapping from the "sender" fields, and send an ARP reply.
  // If type is ARP reply, learn a mapping from the "sender" fields.
  std::optional<InternetDatagram> recv_frame( const EthernetFrame& frame );

  // Called periodically when time elapses
  void tick( size_t ms_since_last_tick );

  // -- My Helper Functions --

  // Make an ARP message
  ARPMessage makeArp( const uint16_t opcode,
    const EthernetAddress sender_ethernet_address,
    const uint32_t sender_ip_address,
    const EthernetAddress target_ethernet_address,
    const uint32_t target_ip_address );

  // Make an Ethernet frame
  EthernetFrame makeFrame( const EthernetAddress& src, // source MAC address
        const EthernetAddress& dst, // destination MAC address
        const uint16_t type, 
        std::vector<Buffer> payload );

  /***
  * Check if an entry is in the ARP table
  * 
  * Checks if an entry with the corresponding ip_address is in the ARP table
  * 
  * found = 0 - if entry is not found
  * found = 1 - if entry is found but is incomplete
  * found = 2 - if entry is found and is complete
  * 
  * index = index of the entry in the ARP table (if found = 1 or 2)...
  *         ...otherwise, index = -1
  */
  void isEntryInARPTable(uint32_t ip_address, int& index, int& found);

  /***
  * Check if an entry is in the IP queues
  * 
  * Checks if an entry with the corresponding ip_address is in the IP queues
  * 
  * found = 0 - if entry is not found
  * found = 1 - if entry is found
  * 
  * index = index of the entry in the IP queues (if found = 1)...
  *         ...otherwise, index = -1
  */
  void isEntryInIPQueues(uint32_t ip_address, int& index, int& found);

};


