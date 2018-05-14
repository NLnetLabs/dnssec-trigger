#include <stdbool.h>

#include "fwd_zones.h"
#include "../vendor/ccan/json/json.h"

#ifdef FWD_ZONES_SUPPORT

struct nm_connection_list yield_connections_from_json(char *json)
{
    struct nm_connection_list ret;
    nm_connection_list_init(&ret);

    if (json_validate(json) == true) {
	//printf("I've got valid json and it looks like this:\n%s\n", json);

	/* Decode the input string and check it again */
	JsonNode *head = json_decode(json);
	if (NULL == head || head->tag != JSON_OBJECT) {
            json_delete(head);
	    return ret;

	}

	/* We expect to get a list of connections. Anything else is not valid input,
	 * even though it might be valid json. */
	JsonNode *node = head->children.head; // now it should be the first dictionary value i.e. connections
	if (NULL == node || strncmp(node->key, "connections", 11) != 0) { // and also must be an array
            json_delete(head);
	    return ret;
	}

        /* Now we finally have the array of connections and this is
         * its head */
        JsonNode *connection = node->children.head;
        /* Go through all connections and put them into the connection list ret */
        while (NULL != connection) {

            struct nm_connection *new_conn = (struct nm_connection *)calloc_or_die(sizeof(struct nm_connection));
            nm_connection_init(new_conn);

            /* Read all key:value pairs in each node. Expected values
             * are: default, servers, type, zones */
            JsonNode *parameter = connection->children.head;
            while (NULL != parameter) {

                // Check JSON key
                if (JSON_BOOL == parameter->tag && strncmp(parameter->key, "default", 7) == 0) {
                    new_conn->default_con = parameter->bool_;
                } else if (JSON_STRING == parameter->tag && strncmp(parameter->key, "type", 4) == 0) {
                    if (strncmp(parameter->string_, "wifi", 4) == 0) {
                        new_conn->type = NM_CON_WIFI;
                    } else if (strncmp(parameter->string_, "vpn", 3) == 0) {
                        new_conn->type = NM_CON_VPN;
                    } else if (strncmp(parameter->string_, "other", 5) == 0) {
                        new_conn->type = NM_CON_OTHER;
                    } else {
                        new_conn->type = NM_CON_IGNORE;
                    }
                } else if (JSON_ARRAY == parameter->tag && strncmp(parameter->key, "zones", 5) == 0) {
                    JsonNode *zone = parameter->children.head;
                    while (NULL != zone) {
                        string_list_push_back(&new_conn->zones, zone->string_, strlen(zone->string_));
                        zone = zone->next;
                    }
                } else if (JSON_ARRAY == parameter->tag && strncmp(parameter->key, "servers", 7) == 0) {
                    JsonNode *server = parameter->children.head;
                    while (NULL != server) {
                        string_list_push_back(&new_conn->servers, server->string_, strlen(server->string_));
                        server = server->next;
                    }
                } else {
                    // TODO: debug output: invalid json key
                }

                parameter = parameter->next;
            }

            nm_connection_list_push_back(&ret, new_conn);
            connection = connection->next;
        }
        json_delete(head);
    } else {
	printf("Invalid json input\n");
        // TODO: log error message into syslog
    }

    return ret;

}

#endif
