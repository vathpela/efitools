/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup identification identification
 * @{ @ingroup utils
 */


#ifndef IDENTIFICATION_H_
#define IDENTIFICATION_H_

typedef enum id_type_t id_type_t;
typedef struct identification_t identification_t;
typedef enum id_match_t id_match_t;
typedef enum id_part_t id_part_t;

#include "chunk.h"
#include "enumerator.h"

/**
 * Matches returned from identification_t.match
 */
enum id_match_t {
	/* no match */
	ID_MATCH_NONE = 0,
	/* match to %any ID */
	ID_MATCH_ANY = 1,
	/* match with maximum allowed wildcards */
	ID_MATCH_MAX_WILDCARDS = 2,
	/* match with only one wildcard */
	ID_MATCH_ONE_WILDCARD = 19,
	/* perfect match, won't get better */
	ID_MATCH_PERFECT = 20,
};

/**
 * ID Types in a ID payload.
 */
enum id_type_t {

	/**
	 * private type which matches any other id.
	 */
	ID_ANY = 0,

	/**
	 * ID data is a single four (4) octet IPv4 address.
	 */
	ID_IPV4_ADDR = 1,

	/**
	 * ID data is a fully-qualified domain name string.
	 * An example of a ID_FQDN is "example.com".
	 * The string MUST not contain any terminators (e.g., NULL, CR, etc.).
	 */
	ID_FQDN = 2,

	/**
	 * ID data is a fully-qualified RFC822 email address string.
	 * An example of an ID_RFC822_ADDR is "jsmith@example.com".
	 * The string MUST NOT contain any terminators.
	 */
	ID_USER_FQDN   = 3,	/* IKEv1 only */
	ID_RFC822_ADDR = 3,	/* IKEv2 only */

	/**
	 * ID data is an IPv4 subnet (IKEv1 only)
	 */
	ID_IPV4_ADDR_SUBNET = 4,

	/**
	 * ID data is a single sixteen (16) octet IPv6 address.
	 */
	ID_IPV6_ADDR = 5,

	/**
	 * ID data is an IPv6 subnet (IKEv1 only)
	 */
	ID_IPV6_ADDR_SUBNET = 6,

	/**
	 * ID data is an IPv4 address range (IKEv1 only)
	 */
	ID_IPV4_ADDR_RANGE = 7,

	/**
	 * ID data is an IPv6 address range (IKEv1 only)
	 */
	ID_IPV6_ADDR_RANGE = 8,

	/**
	 * ID data is the binary DER encoding of an ASN.1 X.501 Distinguished Name
	 */
	ID_DER_ASN1_DN = 9,

	/**
	 * ID data is the binary DER encoding of an ASN.1 X.509 GeneralName
	 */
	ID_DER_ASN1_GN = 10,

	/**
	 * ID data is an opaque octet stream which may be used to pass vendor-
	 * specific information necessary to do certain proprietary
	 * types of identification.
	 */
	ID_KEY_ID = 11,

	/**
	 * private type which represents a GeneralName of type URI
	 */
	ID_DER_ASN1_GN_URI = 201,

	/**
	 * Private ID used by the pluto daemon for opportunistic encryption
	 */
	ID_MYID = 203,
};

/**
 * Type of an ID sub part.
 */
enum id_part_t {
	/** Username part of an RFC822_ADDR */
	ID_PART_USERNAME,
	/** Domain part of an RFC822_ADDR */
	ID_PART_DOMAIN,

	/** Top-Level domain of a FQDN */
	ID_PART_TLD,
	/** Second-Level domain of a FQDN */
	ID_PART_SLD,
	/** Another Level domain of a FQDN */
	ID_PART_ALD,

	/** Country RDN of a DN */
	ID_PART_RDN_C,
	/** CommonName RDN of a DN */
	ID_PART_RDN_CN,
	/** Description RDN of a DN */
	ID_PART_RDN_D,
	/** Email RDN of a DN */
	ID_PART_RDN_E,
	/** EmployeeNumber RDN of a DN */
	ID_PART_RDN_EN,
	/** GivenName RDN of a DN */
	ID_PART_RDN_G,
	/** Initials RDN of a DN */
	ID_PART_RDN_I,
	/** DN Qualifier RDN of a DN */
	ID_PART_RDN_DNQ,
	/** UniqueIdentifier RDN of a DN */
	ID_PART_RDN_ID,
	/** Locality RDN of a DN */
	ID_PART_RDN_L,
	/** Name RDN of a DN */
	ID_PART_RDN_N,
	/** Organization RDN of a DN */
	ID_PART_RDN_O,
	/** OrganizationUnit RDN of a DN */
	ID_PART_RDN_OU,
	/** Surname RDN of a DN */
	ID_PART_RDN_S,
	/** SerialNumber RDN of a DN */
	ID_PART_RDN_SN,
	/** StateOrProvince RDN of a DN */
	ID_PART_RDN_ST,
	/** Title RDN of a DN */
	ID_PART_RDN_T,
};

/**
 * Generic identification, such as used in ID payload.
 *
 * @todo Support for ID_DER_ASN1_GN is minimal right now. Comparison
 * between them and ID_IPV4_ADDR/RFC822_ADDR would be nice.
 */
struct identification_t {

	/**
	 * Get the encoding of this id, to send over
	 * the network.
	 *
	 * Result points to internal data, do not free.
	 *
	 * @return 			a chunk containing the encoded bytes
	 */
	chunk_t (*get_encoding) (identification_t *this);

	/**
	 * Get the type of this identification.
	 *
	 * @return 			id_type_t
	 */
	id_type_t (*get_type) (identification_t *this);

	/**
	 * Check if two identification_t objects are equal.
	 *
	 * @param other		other identification_t object
	 * @return 			TRUE if the IDs are equal
	 */
	bool (*equals) (identification_t *this, identification_t *other);

	/**
	 * Check if an ID matches a wildcard ID.
	 *
	 * An identification_t may contain wildcards, such as
	 * *.strongswan.org. This call checks if a given ID
	 * (e.g. tester.strongswan.org) belongs to a such wildcard
	 * ID. Returns > 0 if
	 * - IDs are identical
	 * - other is of type ID_ANY
	 * - other contains a wildcard and matches this
	 *
	 * The larger the return value is, the better is the match. Zero means
	 * no match at all, 1 means a bad match, and 2 a slightly better match.
	 *
	 * @param other		the ID containing one or more wildcards
	 * @param wildcards	returns the number of wildcards, may be NULL
	 * @return 			match value as described above
	 */
	id_match_t (*matches) (identification_t *this, identification_t *other);

	/**
	 * Check if an ID is a wildcard ID.
	 *
	 * If the ID represents multiple IDs (with wildcards, or
	 * as the type ID_ANY), TRUE is returned. If it is unique,
	 * FALSE is returned.
	 *
	 * @return 			TRUE if ID contains wildcards
	 */
	bool (*contains_wildcards) (identification_t *this);

	/**
	 * Create an enumerator over subparts of an identity.
	 *
	 * Some identities are built from several parts, e.g. an E-Mail consists
	 * of a username and a domain part, or a DistinguishedName contains several
	 * RDNs.
	 * For identity without subtypes (support), an empty enumerator is
	 * returned.
	 *
	 * @return			an enumerator over (id_part_t type, chunk_t data)
	 */
	enumerator_t* (*create_part_enumerator)(identification_t *this);

	/**
	 * Clone a identification_t instance.
	 *
	 * @return 			clone of this
	 */
	identification_t *(*clone) (identification_t *this);

	/**
	 * Destroys a identification_t object.
	 */
	void (*destroy) (identification_t *this);
};

/**
 * creates an ascii representation of a DN
 *
 * @param dn	chunk pointing to DN
 * @param buf	buffer to have string written to it
 * @param len	length of buf
 */
void dntoa(chunk_t dn, STR *buf, size_t len);

#endif /** IDENTIFICATION_H_ @}*/
