#include "network_interface.hh"
#include "arp_message.hh"
#include "ethernet_frame.hh"

using namespace std;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface(const EthernetAddress& ethernet_address, 
                                   const Address& ip_address) : 
    ethernet_address_(ethernet_address), 
    ip_address_(ip_address),
    // Explicitly default-construct the vector members
    ARPTable(),
    ReadyToBeSentQueue(),
    IPQueues() {

    cerr << "DEBUG: Network interface has Ethernet address ";
    cerr << to_string(ethernet_address_);
    cerr << " and IP address ";
    cerr << ip_address.ip() << "\n";
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram(const InternetDatagram& dgram, 
                                     const Address& next_hop){
    int indexARPTable = -999;
    int foundARPTable = -999;
    uint32_t next_hop_ip_address = next_hop.ipv4_numeric();

    isEntryInARPTable(next_hop_ip_address, indexARPTable, foundARPTable);

    // Entry is found and complete
    if(foundARPTable == 2){ 

        EthernetFrame frame = makeFrame(ethernet_address_, 
                                        ARPTable[indexARPTable].mac_address, 
                                        EthernetHeader::TYPE_IPv4, 
                                        serialize(dgram));

        ReadyToBeSentQueue.push_back(frame);

    } 


    // Entry is found but incomplete
    if(foundARPTable == 1){ 

        // If an entry is found in the ARP table but is incomplete,...
        // ...there must be a corresponding entry in the IP queues

        int indexIPQueues = -999;
        int foundIPQueues = -999;

        isEntryInIPQueues(next_hop_ip_address, indexIPQueues, foundIPQueues);

        // Sanity check/Error checking
        if(foundIPQueues != 1){
            cerr << "ERROR: Entry not found in IP queues but found in ARP table\n";
            exit(1);
        }

        // If we reach here, that means foundIPQueues = 1

        // Adding the datagram to the corresponding IP queue
        IPQueues[indexIPQueues].datagrams.push_back(dgram);

        // TODO: Confirm if the following is correct! -> (PS: I think it is correct)
        // Note: I am not updating the TTL of the entry in the...
        // ...ARP table back to 5 seconds

    }


    // Entry is not found
    if(foundARPTable == 0){ 

        // If an entry is not found in the ARP table, then it...
        // ...must not be found in the IP queues

        int indexIPQueues = -999;
        int foundIPQueues = -999;

        isEntryInIPQueues(next_hop_ip_address, indexIPQueues, foundIPQueues);

        // Sanity check/Error checking
        if(foundIPQueues != 0){
            cerr << "ERROR: Entry found in IP queues but not found in ARP table\n";
            exit(1);
        }


        // If we reach here, that means foundIPQueues = 0


        // Adding an entry to the ARP table
        // The entry must be an incomplete entry because we don't...
        // ...know the dest MAC address
        // The TTL of this entry is set to 5 seconds
        ARPTableEntry entry;
        entry.complete_entry = false;
        entry.ip_address = next_hop_ip_address;
        entry.mac_address = {}; // Since we don't know the corresponding MAC address
        entry.ttl = 5000; // 5 seconds

        ARPTable.push_back(entry);


        // Adding an entry to the IP queues
        IPQueue ip_queue;
        ip_queue.ip_address = next_hop_ip_address;
        ip_queue.datagrams.push_back(dgram);

        IPQueues.push_back(ip_queue);

        // Creating an ARP request
        ARPMessage arp = makeArp(ARPMessage::OPCODE_REQUEST, 
                                  ethernet_address_, 
                                  ip_address_.ipv4_numeric(), 
                                  {}, 
                                  next_hop_ip_address);

        // Creating an Ethernet frame for the ARP request
        EthernetFrame frame = makeFrame(ethernet_address_, 
                                        ETHERNET_BROADCAST, 
                                        EthernetHeader::TYPE_ARP, 
                                        serialize(arp));


        // TODO: Confirm if the following is correct! -> (PS: I think it is correct)
        // Adding the frame to the ReadyToBeSentQueue
        ReadyToBeSentQueue.push_back(frame);

    }

    // TODO: You can comment out this error check (Seems like an Overkill)
    // Sanity check/Error checking
    if(foundARPTable == 0 || foundARPTable == 1 || foundARPTable == 2){
        return; // All sucessful
    } else {
        cerr << "ERROR: Something went wrong in the send_datagram() function\n";
        exit(1);
    }

}

// frame: the incoming Ethernet frame
optional<InternetDatagram> NetworkInterface::recv_frame(const EthernetFrame& frame) {
    
    // Checking if a frame is destined for this interface or not
    // A frame is destined for this interface if - 
    // 1) its destination MAC address matches the interface’s MAC address or 
    // 2) if it is broadcast to the whole network.

    // If the frame is not destined for this interface, discard it.
    if( !(frame.header.dst == ethernet_address_ || frame.header.dst == ETHERNET_BROADCAST) ){
        return {};
    }

    // If we reach here, this means that the frame is destined for this interface

    // Checking if the frame contains an IPv4 packet
    if(frame.header.type == EthernetHeader::TYPE_IPv4){
        
        // Parsing the frame to get the datagram
        InternetDatagram dgram;
        if(parse(dgram, frame.payload)){
            return dgram;
        } else {
            return {}; // Parse was unsuccessful
        }

    }


    // Checking if the frame contains an ARP message
    if(frame.header.type == EthernetHeader::TYPE_ARP){

        // Parsing the frame to get the ARP message
        ARPMessage arp;
        if(parse(arp, frame.payload)){

            EthernetAddress sender_ethernet_address = arp.sender_ethernet_address;
            uint32_t sender_ip_address = arp.sender_ip_address;

            int indexARPTable = -999;
            int foundARPTable = -999;

            isEntryInARPTable(sender_ip_address, indexARPTable, foundARPTable);

            int indexIPQueues = -999;
            int foundIPQueues = -999;

            isEntryInIPQueues(sender_ip_address, indexIPQueues, foundIPQueues);

            // STEP 1:
            // Updating the ARP cache table (and IP queues) based on the ARP message
            // To be done for both ARP request and ARP response

            // Case: Entry is found and complete
            if(foundARPTable == 2){

                // No IP queues to process since no IP queues should exist...
                // ...in this case i.e. for a complete entry

                // Sanity check/Error checking
                if(foundIPQueues != 0){
                    cerr << "ERROR: Entry found in IP queues\n";
                    exit(1);
                }

                // If we reach here, that means foundIPQueues = 0
                
                // TODO: Confirm this! -> (PS: I think it is correct)
                // Update the TTL of the entry in the ARP table back to 30 seconds
                ARPTable[indexARPTable].ttl = 30000;

            }


            // Case: Entry is found but incomplete
            if(foundARPTable == 1){

                // If an entry is found in the ARP table but is incomplete,...
                // ...there must be a corresponding entry in the IP queues

                // Sanity check/Error checking
                if(foundIPQueues != 1){
                    cerr << "ERROR: Entry not found in IP queues but found in ARP table\n";
                    exit(1);
                }

                // If we reach here, that means foundIPQueues = 1

                // Updating the MAC address of the entry in the ARP table
                ARPTable[indexARPTable].mac_address = sender_ethernet_address;
                ARPTable[indexARPTable].complete_entry = true;
                // Updating the TTL of the entry in the ARP table to 30 seconds from 5 seconds
                ARPTable[indexARPTable].ttl = 30000;

                // TODO: Confirm if we need to process the IP Queue! -> (PS: I think we need to!)
                // Processing the IP queue
                for(int i = 0; i < static_cast<int>(IPQueues[indexIPQueues].datagrams.size()); i++){

                    // Creating an Ethernet frame for the datagram
                    EthernetFrame new_frame = makeFrame(ethernet_address_, 
                                                    sender_ethernet_address, 
                                                    EthernetHeader::TYPE_IPv4, 
                                                    serialize(IPQueues[indexIPQueues].datagrams[i]));

                    // Adding the frame to the ReadyToBeSentQueue
                    ReadyToBeSentQueue.push_back(new_frame);

                }

                // Removing the entry from the IP queues
                IPQueues.erase(IPQueues.begin() + indexIPQueues);

            }


            // Case: Entry is not found
            if(foundARPTable == 0){

                // If an entry is not found in the ARP table, then...
                // ...no IP queues should exist for that entry
                // Thus, there should be no IP queues to process

                // Sanity check/Error checking
                if(foundIPQueues != 0){
                    cerr << "ERROR: Entry found in IP queues but not in ARP table\n";
                    exit(1);
                }

                // If we reach here, that means foundIPQueues = 0

                // Adding an entry to the ARP table
                // The entry must be a complete entry because we know the dest MAC address
                // The TTL of this entry is set to 30 seconds
                ARPTableEntry entry;
                entry.complete_entry = true;
                entry.ip_address = sender_ip_address;
                entry.mac_address = sender_ethernet_address;
                entry.ttl = 30000; // 30 seconds

                ARPTable.push_back(entry);

            }


            // STEP 2:

            // Note: If this message was an arp response, we have already done...
            // ...the work of processing it by updating the ARP cache table...
            // ...(and IP queues) in STEP 1 (above).

            // If this message was an arp request, we need to send an arp response.
            // PS: We have done pre-processing in STEP 1 for the arp request...
            // ...i.e. we have updated the ARP cache table (and IP queues)

            // Checking if the ARP message is an ARP request
            if(arp.opcode == ARPMessage::OPCODE_REQUEST){

                // We only need to respond to ARP requests that ask for our IP address
                if(arp.target_ip_address == ip_address_.ipv4_numeric()){

                    // Creating an ARP response
                    ARPMessage arp_response = makeArp(ARPMessage::OPCODE_REPLY, 
                                                    ethernet_address_, 
                                                    ip_address_.ipv4_numeric(), 
                                                    sender_ethernet_address, 
                                                    sender_ip_address);

                    // Creating an Ethernet frame for the ARP response
                    EthernetFrame new_frame = makeFrame(ethernet_address_, 
                                                    sender_ethernet_address, 
                                                    EthernetHeader::TYPE_ARP, 
                                                    serialize(arp_response));

                    // Adding the frame to the ReadyToBeSentQueue
                    ReadyToBeSentQueue.push_back(new_frame);
                }

            }

            return {}; // Successfully processed the arp message

        } else {
            return {}; // Parse was unsuccessful
        }

    }

    return {};

}

// ms_since_last_tick: the number of milliseconds since the last call to this method
void NetworkInterface::tick(const size_t ms_since_last_tick){
    
    // Going through each entry in the ARP table
    for(int i = 0; i < static_cast<int>(ARPTable.size()); i++){

        // Reducing the TTL of the entry in the ARP table
        ARPTable[i].ttl -= static_cast<int>(ms_since_last_tick);

        // If the TTL of an entry in the ARP table reaches 0...
        // ...(or becomes negative), remove the entry
        if(ARPTable[i].ttl <= 0){

            // If entry is complete, no need to remove IP queues...
            // ...since there should be no IP queues for a complete entry

            // If entry is incomplete, remove the corresponding IP queues...
            // ...since there should be a corresponding IP queue for an incomplete entry
            if(!ARPTable[i].complete_entry){

                int indexIPQueues = -999;
                int foundIPQueues = -999;

                isEntryInIPQueues(ARPTable[i].ip_address, indexIPQueues, foundIPQueues);

                // Sanity check/Error checking
                if(foundIPQueues != 1){
                    cerr << "ERROR: Entry not found in IP queues\n";
                    exit(1);
                }

                // If we reach here, that means foundIPQueues = 1

                // Removing the entry from the IP queues
                IPQueues.erase(IPQueues.begin() + indexIPQueues);

            }

            // Removing the entry from the ARP table
            ARPTable.erase(ARPTable.begin() + i);
            i--; // Since we have removed an entry
        }
    }

}

optional<EthernetFrame> NetworkInterface::maybe_send()
{   
    // Check if there are any frames in the ReadyToBeSentQueue
    if(static_cast<int>(ReadyToBeSentQueue.size()) > 0){
        
        // Get the first frame in the ReadyToBeSentQueue
        EthernetFrame frame = ReadyToBeSentQueue[0];

        // Remove the frame from the ReadyToBeSentQueue
        ReadyToBeSentQueue.erase(ReadyToBeSentQueue.begin());

        return frame;

    } else {
        return {};
    }

    return {};

}


// -- My Helper functions --

// Make an ARP message
ARPMessage NetworkInterface::makeArp( const uint16_t opcode,
                     const EthernetAddress sender_ethernet_address,
                     const uint32_t sender_ip_address,
                     const EthernetAddress target_ethernet_address,
                     const uint32_t target_ip_address )
{
  ARPMessage arp;
  arp.opcode = opcode;
  arp.sender_ethernet_address = sender_ethernet_address;
  arp.sender_ip_address = sender_ip_address;
  arp.target_ethernet_address = target_ethernet_address;
  arp.target_ip_address = target_ip_address;
  return arp;
}

// Make an Ethernet frame
EthernetFrame NetworkInterface::makeFrame( const EthernetAddress& src,
                          const EthernetAddress& dst,
                          const uint16_t type,
                          vector<Buffer> payload )
{
  EthernetFrame frame;
  frame.header.src = src;
  frame.header.dst = dst;
  frame.header.type = type;
  frame.payload = std::move( payload );
  return frame;
}

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
void NetworkInterface::isEntryInARPTable(uint32_t ip_address, int& index, int& found){
    
    for(int i = 0; i < static_cast<int>(ARPTable.size()); i++){

        if(ARPTable[i].ip_address == ip_address){
            index = i; 
            if(ARPTable[i].complete_entry){
                found = 2; 
            } else {
                found = 1; 
            }
            return; 
        }
    }

    // No entry found
    found = 0;
    index = -1;
    
}

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
void NetworkInterface::isEntryInIPQueues(uint32_t ip_address, int& index, int& found){
    
    for(int i = 0; i < static_cast<int>(IPQueues.size()); i++){

        if(IPQueues[i].ip_address == ip_address){
            index = i; 
            found = 1; 
            return; 
        }
    }

    // No entry found
    found = 0;
    index = -1;
    
}