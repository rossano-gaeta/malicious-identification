/*
 This code was written by Rossano Gaeta in December 2022

 It implements the op algorithm proposed in the following paper:

Rossano Gaeta
"An accurate and efficient algorithm to identify malicious nodes of a graph"
IEEE Transactions on Information Forensics & Security, 2024

 For any question, please contact Rossano Gaeta (rossano.gaeta@unito.it)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <igraph.h>
#include <igraph_games.h>

#define HONEST 111
#define MALICIOUS 112
#define TBD 10

#define FALSE 0
#define TRUE 1

#define UNCERTAIN -1

#define TN 0
#define TP 1
#define FN 2
#define FP 3

#define MAX_STRING 256

unsigned int tp = 0, tn = 0, fp = 0, fn = 0;

igraph_vector_int_t actual_status;

char *guessed_status = NULL;
char *enqueued = NULL;

unsigned int network_size = 0;
unsigned int seed = 31415;

igraph_integer_t distance = 1;

igraph_rng_t *rng; 

igraph_t *graph;
igraph_t original_graph,*component;
igraph_graph_list_t complist;

igraph_vector_int_list_t graph_neighborhood;
igraph_vector_int_t graph_neighborhood_size;

igraph_vector_int_t degrees;

typedef struct node { 
	igraph_integer_t chosen_node;
	igraph_integer_t comparator;
	struct node* next; 

} Node; 

Node* HEAD = NULL;
Node* TAIL = NULL;

Node *free_h = NULL;
unsigned int n_free = 0;

FILE *fp_malicious = NULL;
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
Node* newNode(igraph_integer_t chosen_node, igraph_integer_t comparator){
	Node* temp;

	if(free_h == NULL){
		temp = (Node*)malloc(sizeof(Node)); 
	}
	else{
		temp = free_h;
		free_h = free_h->next;
		n_free--;
	}
	temp->chosen_node = chosen_node; 
	temp->comparator = comparator; 
	temp->next = NULL; 
	return temp; 
} 
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void dequeue(Node** head, Node** tail) { 
	Node* temp = *head; 
	(*head) = (*head)->next; 
	if(*head == NULL)
		(*tail) = NULL;

	if(free_h == NULL){
		free_h = temp;
		free_h->next = NULL;
	}
	else{
		temp->next = free_h;
		free_h = temp;
	}
	n_free++;
} 
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void enqueue(Node** head, Node** tail, igraph_integer_t chosen_node, igraph_integer_t comparator){
	Node * temp;

	if(free_h == NULL){
		temp = (Node*)malloc(sizeof(Node)); 
	}
	else{
		temp = free_h;
		free_h = free_h->next;
		n_free--;
	}
	temp->chosen_node = chosen_node; 
	temp->comparator = comparator; 
	temp->next = NULL; 

	if(*tail != NULL){
		(*tail)->next = temp; 
	}
	(*tail) = temp; 
	if(*head == NULL)
		(*head) = temp; 
} 
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
int isEmpty(Node** head) { return (*head) == NULL; } 
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void deallocate_queue_structures(){
	Node* temp;
	while (HEAD != NULL){
		temp = HEAD;
		HEAD = HEAD->next;
		free(temp);
	}
	while (free_h != NULL){
		temp = free_h;
		free_h = free_h->next;
		free(temp);
	}
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void allocate_vectors(){
	igraph_vector_int_init(&actual_status, network_size);
	guessed_status = (char *)calloc(network_size, sizeof(char));
	enqueued = (char *)calloc(network_size, sizeof(char));
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void deallocate_vectors(){
	igraph_vector_int_destroy(&actual_status);
	free(guessed_status);
	free(enqueued);
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void set_node_statuses(){
	unsigned int node_id;
	size_t len = 0;
	char * line = NULL;
        char *p;

	for(node_id = 0; node_id < network_size; node_id++){
		enqueued[node_id] = FALSE;
		VECTOR(actual_status)[node_id] = HONEST;
		guessed_status[node_id] = TBD;
	}

	getline(&line, &len, fp_malicious);
	p = line;
	while(*p != '\0'){
        	sscanf(p, "%u",&node_id);
		if(VECTOR(actual_status)[node_id] != MALICIOUS)
			VECTOR(actual_status)[node_id] = MALICIOUS;
		else
			fprintf(stdout,"Warning: node %u is more than once listed as malicious\n",node_id);
        	while((*p) != ' ' && (*p) != '\0') 
			p++;
        	if((*p) == ' ') 
			p++;
	}
	if (line)
		free(line);
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
void compute_node_results(igraph_integer_t chosen, igraph_integer_t comparator, igraph_integer_t chosen_degree){
	if( guessed_status[chosen] == VECTOR(actual_status)[chosen]){/* Hit */ 
		if(VECTOR(actual_status)[chosen] == HONEST)
			tn++;
		else
			tp++;
	}/* Hit */
	else{/* Miss */
		if(VECTOR(actual_status)[chosen] == HONEST)
			fp++;
		else
			fn++;
	}/* Miss */
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
char compute_node_status(igraph_integer_t chosen, int comparator){
	char ret = TRUE;

	igraph_integer_t comparator_neighborhood_size = VECTOR(graph_neighborhood_size)[comparator];
	igraph_integer_t to_insert = comparator_neighborhood_size - 1; 
	igraph_integer_t n_inserted = 0;
	igraph_integer_t comparator_neighbor_index = 0; 

	for(; n_inserted < to_insert && ret; ){
		igraph_integer_t one_neighbor_of_comparator = VECTOR(VECTOR(graph_neighborhood)[comparator])[comparator_neighbor_index];
		if(one_neighbor_of_comparator != chosen){
			char comparison;
			if(VECTOR(actual_status)[chosen] == HONEST && VECTOR(actual_status)[one_neighbor_of_comparator] == HONEST)
				comparison = FALSE;
			else
				comparison = TRUE;
			if(VECTOR(actual_status)[comparator] == MALICIOUS && igraph_rng_get_unif01(rng) <= 0.5){
				if(comparison == TRUE)
					comparison = FALSE;
				else
					comparison = TRUE;
			}
			n_inserted++;
			ret &= comparison;
		}
		comparator_neighbor_index++;
	}
	return ret;
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
unsigned int guess_node_status(igraph_integer_t chosen, igraph_integer_t comparator){
	unsigned int n_honest_guesses = 0;
	unsigned int n_malicious_guesses = 0;
	unsigned int status = 999;
	igraph_integer_t chosen_degree = VECTOR(degrees)[chosen];
	igraph_integer_t comparator_for_chosen_degree;

	switch(comparator){
		case UNCERTAIN:
			n_honest_guesses = 0;
			n_malicious_guesses = 0;
			igraph_integer_t chosen_neighborhood_size = VECTOR(graph_neighborhood_size)[chosen];
			for(igraph_integer_t index = 0; index < chosen_neighborhood_size; index++) {
				igraph_integer_t comparator_for_chosen = VECTOR(VECTOR(graph_neighborhood)[chosen])[index];
				comparator_for_chosen_degree = VECTOR(degrees)[comparator_for_chosen];
				status = (compute_node_status(chosen, comparator_for_chosen))?MALICIOUS:HONEST;
				if(status == HONEST)
					n_honest_guesses++;
				else
					n_malicious_guesses++;
			}
			status = guessed_status[chosen] = (n_honest_guesses >= n_malicious_guesses)?HONEST:MALICIOUS;
			compute_node_results(chosen,comparator,chosen_degree);
			break;
		default:
			comparator_for_chosen_degree = VECTOR(degrees)[comparator];
			status = guessed_status[chosen] = (compute_node_status(chosen, comparator))?MALICIOUS:HONEST;
			compute_node_results(chosen,comparator,chosen_degree);
			break;
	}
	return status;
}
/**************************************************************/
/* NAME : */
/* DESCRIPTION : */
/* PARAMETERS : */
/* RETURN VALUE : */
/**************************************************************/
int main(int argc, char *argv[]) {
	char c, graph_filename[MAX_STRING], malicious_filename[MAX_STRING];

	while ((c = getopt (argc, argv, "g:m:s:h")) != -1)
	switch (c) {
		case 'g':
			sprintf(graph_filename,"%s",optarg);
			break;
		case 'm':
			sprintf(malicious_filename,"%s",optarg);
			break;
		case 's':
			seed = atof(optarg);
			break;
		case 'h':
			fprintf(stdout,"usage: %s -g (graph-filename) -m (malicious-filename) -s (seed) -h (help)\n",argv[0]);
			exit(EXIT_FAILURE);
		default:
			fprintf(stdout,"Abort: something is wrong in command line options\n");
			exit(EXIT_FAILURE);
	}
	
	// Set a random seed to make the program deterministic 
	rng = igraph_rng_default();
	igraph_rng_seed(rng, seed);

	FILE * fp_graph = fopen(graph_filename,"r");
	fp_malicious = fopen(malicious_filename,"r");

	if(igraph_read_graph_edgelist(&original_graph, fp_graph, 0, IGRAPH_UNDIRECTED) ==  IGRAPH_PARSEERROR){
		fprintf(stdout,"PARSING ERRORE READING FILE %s\n",graph_filename);
		exit(EXIT_FAILURE);
	}
	fclose(fp_graph);

	// Compute connected components and extract the largest one
	igraph_graph_list_init(&complist, 0);
	igraph_decompose(&original_graph, &complist, IGRAPH_WEAK, -1, 2);
	unsigned int largest_wcc_index, max_wcc_size = 0;
	for (unsigned int i = 0; i < igraph_graph_list_size(&complist); i++) {
		component = igraph_graph_list_get_ptr(&complist, i);
		igraph_integer_t wcc_size = igraph_vcount(component);
		if(wcc_size > max_wcc_size){
			max_wcc_size = wcc_size;
			largest_wcc_index = i;
		}
	}
	graph = igraph_graph_list_get_ptr(&complist, largest_wcc_index);
	
	// Simplify graph by removing self-loops and multiple arcs
	igraph_simplify(graph, TRUE, TRUE, NULL);
	network_size = igraph_vcount(graph);

	// Allocate all necessary vectors
	allocate_vectors();

	// Compute once for all neighborhood
	igraph_vector_int_init(&degrees, 0);
	igraph_degree(graph, &degrees, igraph_vss_all(), IGRAPH_ALL, IGRAPH_NO_LOOPS);
	igraph_vector_int_list_init(&graph_neighborhood, 0);
	igraph_vs_t vs;
	igraph_vs_all(&vs);
	igraph_neighborhood(graph, &graph_neighborhood, vs, distance, IGRAPH_ALL, distance);
	igraph_vector_int_init(&graph_neighborhood_size, network_size);
	for(unsigned int node_id = 0; node_id < network_size; node_id++)
		VECTOR(graph_neighborhood_size)[node_id] = igraph_vector_int_size(igraph_vector_int_list_get_ptr(&graph_neighborhood, node_id));

	// Reset all counters and set nodes status
	tp = 0, tn = 0, fp = 0, fn = 0;
	set_node_statuses(); 

	// Start the op algorithm
	do{
		for(unsigned int chosen_ind = 0; chosen_ind < network_size; chosen_ind++){
			igraph_integer_t chosen = chosen_ind;
			if(guessed_status[chosen] == TBD){
				unsigned int status = guess_node_status(chosen, UNCERTAIN);
				if(status == HONEST && VECTOR(graph_neighborhood_size)[chosen] > 1){
					igraph_integer_t fixed_comparator = chosen;
					igraph_integer_t chosen_neighborhood_size = VECTOR(graph_neighborhood_size)[chosen];
					for(igraph_integer_t index = 0; index < chosen_neighborhood_size; index++) {
						igraph_integer_t neigh = VECTOR(VECTOR(graph_neighborhood)[chosen])[index];
						if(!enqueued[neigh]){
							enqueue(&HEAD, &TAIL, neigh, fixed_comparator);
							enqueued[neigh] = TRUE;
						}
					}
					break;
				}
			}
		}
		while (HEAD != NULL) { 
			igraph_integer_t chosen = (HEAD)->chosen_node;
			if(guessed_status[chosen] == TBD){
				igraph_integer_t fixed_comparator = (HEAD)->comparator;
				dequeue(&HEAD, &TAIL); 
				unsigned int status = guess_node_status(chosen, fixed_comparator);
				if(status == HONEST && VECTOR(graph_neighborhood_size)[chosen] > 1){
					igraph_integer_t fixed_comparator = chosen;
					igraph_integer_t chosen_neighborhood_size = VECTOR(graph_neighborhood_size)[chosen];
					for(igraph_integer_t index = 0; index < chosen_neighborhood_size; index++) {
						igraph_integer_t neigh = VECTOR(VECTOR(graph_neighborhood)[chosen])[index];
						if(!enqueued[neigh]){
							enqueue(&HEAD, &TAIL, neigh, fixed_comparator);
							enqueued[neigh] = TRUE;
						}

					}
				}
			}
			else
				dequeue(&HEAD, &TAIL); 
		} 
	} while(tp + tn + fp + fn < network_size);

	fprintf(stdout,"TP %u : TN %u : FP %u : FN %u = %u ",tp,tn,fp,fn,tp+tn+fp+fn);

	// Release all memory and close files
	
	igraph_vector_int_destroy(&degrees);
	igraph_vector_int_list_destroy(&graph_neighborhood);
	igraph_vector_int_destroy(&graph_neighborhood_size);
	igraph_destroy(&original_graph);
	igraph_graph_list_clear(&complist);
	igraph_graph_list_destroy(&complist);

	deallocate_queue_structures();
	deallocate_vectors();

	fclose(fp_malicious);
	return EXIT_SUCCESS;
}
