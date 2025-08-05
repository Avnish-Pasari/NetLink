#include "router.hh"

#include <iostream>
#include <limits>

using namespace std;

// Default constructor for Router.
Router::Router()
  : interfaces_(), RoutingTable() {
    cerr << "DEBUG: Router constructed with " 
              << interfaces_.size() << " interface(s) and " 
              << RoutingTable.size() << " routing table entries." 
              << endl;
}

// route_prefix: The "up-to-32-bit" IPv4 address prefix to match the datagram's destination address against
// prefix_length: For this route to be applicable, how many high-order (most-significant) bits of
//    the route_prefix will need to match the corresponding bits of the datagram's destination address?
// next_hop: The IP address of the next hop. Will be empty if the network is directly attached to the router (in
//    which case, the next hop address should be the datagram's final destination).
// interface_num: The index of the interface to send the datagram out on.
void Router::add_route( const uint32_t route_prefix,
                        const uint8_t prefix_length,
                        const optional<Address> next_hop,
                        const size_t interface_num )
{
  cerr << "DEBUG: adding route " << Address::from_ipv4_numeric( route_prefix ).ip() << "/"
       << static_cast<int>( prefix_length ) << " => " << ( next_hop.has_value() ? next_hop->ip() : "(direct)" )
       << " on interface " << interface_num << "\n";

  // Creating a new Routing Table Entry
  RoutingTableEntry entry;
  entry.route_prefix = route_prefix;
  entry.prefix_length = prefix_length;
  entry.next_hop = next_hop;
  entry.interface_num = interface_num;

  // Adding the Routing Table Entry to the Routing Table
  RoutingTable.push_back( entry );
}

void Router::route() {

  // Iterating over all interfaces
  for( size_t i = 0; i < interfaces_.size(); i++ ) {

    // Taking out the first datagram from the interface
    optional<InternetDatagram> datagram = interfaces_[i].maybe_receive();

    // Consuming every incoming datagram
    while( datagram.has_value() ) {

      // Checking for the longest prefix match
      RoutingTableEntry table_entry;
      int longest_prefix_length = -999;

      for( size_t j = 0; j < RoutingTable.size(); j++ ) {

        if( isPrefixMatch( datagram->header.dst, RoutingTable[j].route_prefix, RoutingTable[j].prefix_length ) ) {

          if( RoutingTable[j].prefix_length > longest_prefix_length ) {
            longest_prefix_length = RoutingTable[j].prefix_length;
            table_entry = RoutingTable[j];
          }
        }
      }

      // If longest_prefix_length is less than 0, then no match was found ...
      // ... and we should drop and move to the next datagram
      // Otherwise, we should process it
      if( longest_prefix_length >= 0) {

        // Checking the TTL field of the datagram
        // If the TTL field is 0 or 1, then we should drop the datagram
        // Otherwise, we should process it
        if( datagram->header.ttl > 1 ) {

          // Decrementing the TTL field
          datagram->header.ttl--;

          // Recomputing the checksum
          datagram->header.compute_checksum();

          // If the next_hop field is empty, then the network is directly attached to the router
          // In this case, the next_hop address should be the datagram's final destination
          if( table_entry.next_hop.has_value() ) {
            interfaces_[table_entry.interface_num].send_datagram( *datagram, table_entry.next_hop.value() );
          } else {
            interfaces_[table_entry.interface_num].send_datagram( *datagram, Address::from_ipv4_numeric( datagram->header.dst ) );
          }
          
        }

      }
      
      // Checking for the next datagram
      datagram = interfaces_[i].maybe_receive();
    }
    
  }

}



// HELPER FUNCTION

/***
 * Checks if there is a prefix match between two IP addresses
 * 
 * @param ip_address1 The first IP address
 * @param ip_address2 The second IP address
 * @param prefix_length The number of bits to match (0 to 32 inclusive)
 * 
 * @return true if there is a prefix match, false otherwise
 */
bool Router::isPrefixMatch(uint32_t ip_address1, uint32_t ip_address2, uint8_t prefix_length) {
  // If no bits are required to match, return true
  if (prefix_length == 0)
      return true;
  
  // Create a mask that has the first prefix_length bits set to 1.
  // If prefix_length is 32, then the mask is 0xFFFFFFFF.
  uint32_t mask = (prefix_length == 32) ? 0xFFFFFFFF : (~0u << (32 - prefix_length));
  
  // Compare the masked parts of both IP addresses.
  return (ip_address1 & mask) == (ip_address2 & mask);
}