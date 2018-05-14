#if !defined CONNECTION_LIST_H && defined FWD_ZONES_SUPPORT
#define CONNECTION_LIST_H

#include <stdbool.h>
#include <stdarg.h>

#include "string_list.h"
#include "string_buffer.h"

/**
 * All possible types of connections
 * in Network Manager.
 */
enum nm_connection_type {
    NM_CON_VPN,
    NM_CON_WIFI,
    NM_CON_OTHER,
    NM_CON_IGNORE,
    NM_CON_DELIMITER // XXX: What is this??
};

enum nm_connection_security {
    NM_CON_SECURE,
    NM_CON_INSECURE,
    NM_CON_NA, // <- Not applicable
};

/**
 *
 */
enum list_ownership_type {
  LIST_OWNING,
  LIST_NON_OWNING
};

/**
 * "connection" refers to the concept used by
 * NetworkManager. e.g. `$ nmcli con show --active`
 */
struct nm_connection {
    /** Is this connection the default one? */
    bool default_con;
    /** Linked list of zones */
    struct string_list zones;
    /** Type of this connection as defined in enum connection_type */
    enum nm_connection_type type;
    /** Linked list of servers */
    struct string_list servers;
    /** Marker of secure/insecure connections */
    enum nm_connection_security security;
};

/**
 * One node of a list of connections
 */
struct nm_connection_node {
    /** Pointer to this connection struct. */
    struct nm_connection *self;
    /** Pointer to the next connection. */
    struct nm_connection_node *next;
};


/**
 * Linked list of connections.
 * XXX: ?All nodes and its content is owned by this struct.
 */
struct nm_connection_list {
    /** Head of a list */
    struct nm_connection_node *first;
    /** Ownership status of this list */
    enum list_ownership_type ownership;
};

/**
 * Filter function footprint.
 * @param conn: The connection struct to check
 */
typedef bool (*filter_conn_fcn)(struct nm_connection const *);

/**
 * Initialize all members of connection struct
 * @param conn: Connection to be initialized
 */
void nm_connection_init(struct nm_connection *conn);

/**
 * Free all memory used by this struct
 * @param conn: Connection to be freed
 */
void nm_connection_clear(struct nm_connection *conn);

/*
 * Initialize an empty owning list of connections
 * @param list: List to be initialized
 */
void nm_connection_list_init(struct nm_connection_list *list);

/*
 * Initialize an empty non-owning list of connections
 * @param list: List to be initialized
 */
void nm_connection_list_init_non_owning(struct nm_connection_list *list);

/**
 * Free the whole list and all its components (connection nodes and lists of strings)
 * Be careful though, use this only on owning lists. Usage on non-owning lists can cause
 * memory corruption.
 * @param list: List to be freed
 */
void nm_connection_list_clear(struct nm_connection_list *list);

/**
 * Push a new connections into the list. The new connection is now owned by the list. You
 * should not use it elsewhere.
 * @param list: List to push to
 * @param new_value: New connection
 */
void nm_connection_list_push_back(struct nm_connection_list *list, struct nm_connection *new_value);

/**
 * Copy the new_value and then push it back
 * @param list: List to push to
 * @param new_value: New connection
 */
void nm_connection_list_copy_and_push_back(struct nm_connection_list *list, struct nm_connection *new_value);


/**
 * Search for a zone with given name and return if it is present or not
 * @param list: List to search through
 * @param zone: Zone name
 * @param len: Zone name length
 */
bool nm_connection_list_contains_zone(const struct nm_connection_list *list, char *zone, size_t len);

/**
 * Remove the first connection with given zone
 * @param list: List to search through
 * @param zone: Zone name
 * @param len: Zone name length
 */
int nm_connection_list_remove(struct nm_connection_list *list, char *zone, size_t len);

/**
 * 
 * @param list: List to search through
 */
struct string_list nm_connection_list_get_servers_list(struct nm_connection_list *list);

/**
 * Filter connections list and return a new non-owning one, which contains only those connections
 * that satisfy **all** filters.
 * @param list: Original list (will be a superset to the new one)
 * @param count: Number of filters given to this function
 * @return: The new list
 */
struct nm_connection_list nm_connection_list_filter(struct nm_connection_list *list,
        unsigned int count, ...);

/**
 * Measure the length of a list
 * @param list: The list to be measures
 */
size_t nm_connection_list_length(struct nm_connection_list *list);

/**
 * Print the whole list onto stdout.
 * @param list: List to be printed
 */
void nm_connection_list_dbg_print(struct nm_connection_list *list);

/**
 * Print the whole list onto stderr.
 * @param list: List to be printed
 */
void nm_connection_list_dbg_eprint(struct nm_connection_list *list);

/**
 * Print all servers into char buffer. The caller is reposinble for releasing the
 * buffer with free().
 * @param list: List to be printed
 */
struct string_buffer nm_connection_list_sprint_servers(struct nm_connection_list *list);

/**
 * Return true if the connection is VPN
 * @param conn: Single connection to be tested
 */
bool nm_connection_filter_type_vpn(struct nm_connection const *conn);

/**
 * Return true if the connection is default
 * @param conn: Single connection to be tested
 */
bool nm_connection_filter_default(struct nm_connection const *conn);

/**
 * Return true if the connection is of type OTHER
 * @param conn: Single connection to be tested
 */
bool nm_connection_filter_type_other(struct nm_connection const *conn);

#endif /* CONNECTION_LIST_H */
