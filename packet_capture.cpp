#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <assert.h>

#include <pcl/visualization/cloud_viewer.h>
#include <pcl/visualization/pcl_visualizer.h>
#include <pcl/io/io.h>
#include <pcl/io/pcd_io.h>
#include <pcl/point_types.h>
#include <pcl/filters/statistical_outlier_removal.h>
#include <pcl/filters/radius_outlier_removal.h>
#include <pcl/filters/passthrough.h>

#include <boost/thread/thread.hpp>
#include <pcl/common/common_headers.h>
#include <pcl/range_image/range_image.h>
#include <pcl/visualization/range_image_visualizer.h>

#include <string>
#include <fstream>
#include <vector>
#include <stdlib.h>
#include <math.h>

using namespace std;

#define PI 3.14159265

// Define the structs needed to decode ethernet packets
struct fire_data {
	uint16_t block_id;
	double azimuth;
	double dist[32];
	double intensity[32];
};

struct data_packet {
	uint8_t header[42];
	fire_data payload[12];
	uint8_t footer[6];
};

//Define the data structure builder function
//Input: 1248 byte long UDP data packet
//Output: Pointer to the data structure
struct data_packet data_structure_builder(const struct pcap_pkthdr *header, const u_char *data);
pcl::PointCloud<pcl::PointXYZRGBA>::Ptr extract_xyz(data_packet processed_packet);

int user_data;
const int cycle_num = 581;

void viewerOneOff (pcl::visualization::PCLVisualizer& viewer)
{	
    viewer.setBackgroundColor (255,255,255); // black background
	viewer.setPointCloudRenderingProperties(pcl::visualization::PCL_VISUALIZER_POINT_SIZE,2,"cloud"); // size of point clouds
	viewer.setRepresentationToSurfaceForAllActors();
	viewer.addCoordinateSystem (4);
	viewer.initCameraParameters ();
	viewer.setCameraPosition (-20, 0, 60, 0.0, 0, 100);
	
    pcl::PointXYZ o;
    o.x = 0;
    o.y = 0;
    o.z = 0;
}


void viewerPsycho (pcl::visualization::PCLVisualizer& viewer)
{
    static unsigned count = 0;
    std::stringstream ss;
    ss << "Once per viewer loop: " << count++;
    viewer.removeShape ("text", 0);
    user_data++;	
}

void delay()
{
	for(int i = 0; i < 800; i++){
		for (int j = 0; j < 100; j++){}
	}
}

// function declaration for packetHandler
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int global_ctr = 0; // to print out the packet number

pcl::visualization::CloudViewer viewer("Cloud Viewer"); // declare the viewer as a global variable

int main() 
{	
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];

  	// open capture file for offline processing
	descr = pcap_open_offline("Sample_2.pcap", errbuf);
  	if (descr == NULL) {
     	cout << "pcap_open_live() failed: " << errbuf << endl;
     	return 1;
  	}

	viewer.runOnVisualizationThreadOnce (viewerOneOff);
    viewer.runOnVisualizationThread (viewerPsycho);

    //loop through the pcap file and extract the packets
    pcap_loop(descr, 0, packetHandler, NULL);
 
  	cout << "capture finished" << endl;

  	int x = 0;

  	while(x == 0)
	 cin >> x;

  	return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
  	//cout << global_ctr++ << endl;
  	/*// Print the contents of the packet
  	printf("\nPacket # %i\n", global_ctr++);
  	for(int i = 0; i < pkthdr -> len; i++){
  		if((i % 16) == 0) printf("\n");
  			printf("%.2x ", packet[i]);
  	}

  	//Double new lines after printing each packet
  	printf("\n\n");*/

	//assign the packaged ethernet data to the struct
	struct data_packet processed_packet = data_structure_builder(pkthdr, packet);

	//insert function here to extract xyz from processed_packet and return the cloud to be visualized below
	pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);
	cloud = extract_xyz(processed_packet);
	
	//declare the intermediate variable
	// pcl::PointXYZRGBA sample;

	// for(int j = 0; j < 1000; j++){
	// 	int color = rand()%3;
	// 	sample.x = rand()%100 ;
	// 	sample.y = rand()%100 ;
	// 	sample.z = rand()%100 ;

	// 	if(color == 0){
	// 		sample.r = 255; sample.g = 0; sample.b = 0;
	// 	} else if(color == 1) {
	// 		sample.r = 0; sample.g = 255; sample.b = 0;
	// 	} else {
	// 		sample.r = 0; sample.g = 0; sample.b = 255;
	// 	}

	// 	cloud -> points.push_back(sample);
	// }
	
	if(global_ctr == cycle_num) //buffer
		viewer.showCloud(cloud);
	
	delay();
	
	//end the program if the viewer was closed by the user
	if(viewer.wasStopped()){
		cout << "Viewer Stopped" << endl;
		exit(0);
	}    
}


// function definiton for data_structure_builder
struct data_packet data_structure_builder(const struct pcap_pkthdr *pkthdr, const u_char *data)
{
    //printf("Packet size: %d bytes\n", pkthdr->len);		
    if (pkthdr->len != pkthdr->caplen)
        printf("Warning! Capture size different than packet size: %ld bytes\n", (long)pkthdr->len);

	// define the main struct
	struct data_packet first;

	//assert(pkthdr -> len == 1248);

	if(pkthdr -> len != 1248){
		return (const struct data_packet){0};
	}

			
	for(int i = 0; i < 42; i++){
		first.header[i] = data[i]; // fill in the header
	}

	//cout << endl;
	for(int i = 0; i < 6; i++){
		first.footer[i] = data[i + 1242]; // fill in the footer
	}

	// populate the payload (block ID, azimuth, 32 distances, 32 intensities  for each of the 12 data blocks)
	int curr_byte_index = 42; // not 43 bcz. in C++, indexing starts at 0, not 1
	uint8_t curr_firing_data[100];
	fire_data temp[12];

	for(int i = 0; i < 12; i++){
		for(int j = 0; j < 100; j++){
			curr_firing_data[j] = data[j + curr_byte_index];
			//cout << (double)curr_firing_data[j] << endl;
		}
		temp[i].block_id = (curr_firing_data[1] << 8) | (curr_firing_data[0]);
		temp[i].azimuth = (double)((curr_firing_data[3] << 8) | (curr_firing_data[2])) / 100;

		/*cout << temp[0].block_id << " " << temp[0].azimuth << endl;*/

		int ctr = 0;
		for(int j = 0; j < 32; j++){
			temp[i].dist[j] = (double)((curr_firing_data[4 + ctr + 1] << 8) | curr_firing_data[4 + ctr]) / 500;
			temp[i].intensity[j] = curr_firing_data[4 + ctr + 2];
			ctr = ctr + 3;
		}
		first.payload[i] = temp[i];
		curr_byte_index = curr_byte_index + 100;
	}

	return first;
}

//Extracts xyz co-ordinates from processed_packet
//Input: Main Struct
//Output: Pointer to a cloud
pcl::PointCloud<pcl::PointXYZRGBA>::Ptr extract_xyz(struct data_packet processed_packet)
{
	static pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);	
	pcl::PointXYZRGBA sample;

	for(int i = 0; i < 12; i++){
		double curr_azimuth = (processed_packet.payload[i].azimuth) * PI / 180; //convert degrees to radians
		for(int j = 0; j < 32; j++){
			double curr_dist = processed_packet.payload[i].dist[j];
			sample.x = curr_dist * sin(curr_azimuth);
			sample.y = curr_dist * cos(curr_azimuth);
			sample.z = 0;
			sample.r = 255; sample.g = 0; sample.b = 0;
			cloud -> points.push_back(sample);
		}
	}

	if(global_ctr > cycle_num){
		cloud -> points.clear();
		global_ctr = 0;
	}
	global_ctr++;

	return cloud;
}