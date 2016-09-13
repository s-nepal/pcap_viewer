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

using namespace std;

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
data_packet data_structure_builder(const struct pcap_pkthdr *header, const u_char *data); 
int user_data;

void 
viewerOneOff (pcl::visualization::PCLVisualizer& viewer)
{	

    viewer.setBackgroundColor (0,0,0); // black background
	viewer.setPointCloudRenderingProperties(pcl::visualization::PCL_VISUALIZER_POINT_SIZE,2,"cloud"); // size of point clouds
	viewer.setRepresentationToSurfaceForAllActors();
	viewer.addCoordinateSystem (4);
	viewer.initCameraParameters ();
	viewer.setCameraPosition (-20, 0, 60, 0.0, 0, 100);
	

	// add labels for the 3 axes
	/*pcl::PointXYZ pos;
	pos.x = 20; pos.y = 0; pos.z = 0;
	viewer.addText3D("x",pos,2,1.0,0.0,0.0,"x");
	pos.x = 0; pos.y = 20; pos.z = 0;
	viewer.addText3D("y",pos,2,0.0,7,0.0,"y");
	pos.x = 0; pos.y = 0; pos.z = 20;
	viewer.addText3D("z",pos,2,0.0,0.0,20,"z");*/
	
    pcl::PointXYZ o;
    o.x = 0;
    o.y = 0;
    o.z = 0;

   /* viewer.addSphere (o, 15, "sphere", 0);
	viewer.addCube(-1,1,0,1,-1,1,1.0,1.0,1.0,"cube",0);
    std::cout << "i only run once" << std::endl;*/
    
}


void 
viewerPsycho (pcl::visualization::PCLVisualizer& viewer)
{
    static unsigned count = 0;
    std::stringstream ss;
    ss << "Once per viewer loop: " << count++;
    viewer.removeShape ("text", 0);
    //viewer.addText (ss.str(), 200, 300, "text", 0);

    //FIXME: possible race condition here:
    user_data++;	
}

void delay()
{
	for(int i = 0; i < 30000; i++){
		for (int j = 0; j < 10000; j++){}
	}
}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int global_ctr = 0; // to print out the packet number

int main() 
{

	// declare the point cloud class
    pcl::PointCloud<pcl::PointXYZRGBA>::Ptr cloud (new pcl::PointCloud<pcl::PointXYZRGBA>);	
	
	pcl::PointXYZRGBA sample;

	pcl::visualization::CloudViewer viewer("Cloud Viewer");

    //blocks until the cloud is actually rendered
    //viewer.showCloud(cloud);
	viewer.runOnVisualizationThreadOnce (viewerOneOff);
    viewer.runOnVisualizationThread (viewerPsycho);

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  // open capture file for offline processing
  descr = pcap_open_offline("tire.pcap", errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  while(!viewer.wasStopped()){
	  while(pcap_loop(descr, 0, packetHandler, NULL) >= 0){
	  	// The loop will break once the entire .pcap file has been looped through
	  	break;
	  }
	}
  
  cout << "capture finished" << endl;

  return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
  
  // Print the contents of the packet
  /*printf("\nPacket # %i\n", global_ctr++);
  for(int i = 0; i < pkthdr -> len; i++){
  	if((i % 16) == 0) printf("\n");
  	printf("%.2x ", packet[i]);
  }

  // Double new lines after printing each packet
  printf("\n\n");*/

  data_packet processed_packet;
  processed_packet = data_structure_builder(pkthdr, packet);

  // // Accuracy check
  // for(int i = 0; i < 6; i++){
  // 	//if((i % 16) == 0) printf("\n");
  // 	//cout << i << endl;
  // 	//for(int j = 0; j < 32; j++){
  // 		printf("%.2x ", processed_packet.footer[i]);
  // 		//cout << processed_packet.payload[i].dist[j];
  // 		printf("\n");
  // 	///}
  // 	//while(1);	
  // }
  // while(1);
}


// function definiton for data_structure_builder
data_packet data_structure_builder(const struct pcap_pkthdr *pkthdr, const u_char *data)
{
    //printf("Packet size: %d bytes\n", pkthdr->len);
		
    if (pkthdr->len != pkthdr->caplen)
        printf("Warning! Capture size different than packet size: %ld bytes\n", (long)pkthdr->len);

	assert(pkthdr -> len == 1248);

	// define the main struct
	struct data_packet first;
			
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