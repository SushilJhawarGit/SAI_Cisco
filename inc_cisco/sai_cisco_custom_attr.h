/* ----------------------------------------------------------------
 * Copyright (c) 2024 by Cisco Systems, Inc.  and its affiliates
 * All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 * ---------------------------------------------------------------- */


#ifndef __SAI_CISCO_CUSTOM_ATTR_H__
#define __SAI_CISCO_CUSTOM_ATTR_H__

#include <saitypes.h>
#include <saiswitch.h>
#include <saiport.h>
#include <saiacl.h>
#include <saimacsec.h>
#include <saiipsec.h>

/* ###################################################################### */
/* #### Begin: Switch custom attributes #### */
/* ###################################################################### */

/**
 * @brief List of custom switch attributes
 */
typedef enum _sai_switch_attr_custom_t
{

 /**
     * @brief Trigger pmon
     *
     * TRUE - Trigger pmon
     * FALSE - No action.
     *
     * @type bool
     * @flags SET
     * @default FALSE
     */
    SAI_SWITCH_ATTR_CUSTOM_PMON_TRIGGER = SAI_SWITCH_ATTR_CUSTOM_RANGE_START,     

    /**
     * @brief configures serdes physical lane swap parameters
     *
     * The Input is list of  DATAPATH_SERDES_PORT_MAX(48) entries of TX serdes lanes.
     * First 24 entries for Line side and next 24 for Host side
     * Note for 16 lanes per bank variants,only the first 16 lanes are valid
     * set to SERDES_PORT_ID_NIU to be the same as the rx
     * @type uint32_tlist
     * @flags SET
     * @default FALSE
     */
    SAI_SWITCH_ATTR_CUSTOM_SERDES_TX_LANE_SWAP,
    SAI_SWITCH_ATTR_CUSTOM_DEFECTS_SUMMARY,        

    /**
     * @brief Serdes Pin Defects get
     *
     * @type sai_pointer_t
     * @flags GET
     * @default internal
     */
    SAI_SWITCH_ATTR_CUSTOM_DEFECTS,        

/** End of custom range base */
    SAI_SWITCH_ATTR_CUSTOM_RANGE_DEFINED_END,

} sai_switch_attr_custom_t;

/* ###################################################################### */
/* #### End: Switch custom attributes #### */
/* ###################################################################### */

/* ###################################################################### */
/* #### Begin: PORT custom attributes #### */
/* ###################################################################### */

/**
 * @brief List of custom port attributes
 */
typedef enum _sai_port_attr_custom_t
{

    /* @brief Port provision mode
     *
     * @type
     * @flags CREATE_ONLY
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_PORT_PROVISION_MODE = SAI_PORT_ATTR_CUSTOM_RANGE_START,            

     /**
     * @brief Enable/Disable the Alarm relay mode
     *
     *
     * TRUE - Relay mode: 
     * FALSE - Termination mode: 
     *
     * @type bool
     * @flags CREATE_ONLY
     * @default FALSE
     */
    SAI_PORT_ATTR_CUSTOM_ALARM_RELAY_MODE,            

    /**
     * @brief Enable  non-intrusive monitoring (for PCS and analog retimer datapath)
     * @type bool
     * @flags CREATE_ONLY
     * @default FALSE
     */
    SAI_PORT_ATTR_CUSTOM_NIM_MODE,            

    /**
     * @brief Trigger serdes adaptation
     *
     * TRUE - Trigger serdes adaptation
     * FALSE - No action.
     *
     * @type bool
     * @flags SET
     * @default FALSE
     */
    SAI_PORT_ATTR_CUSTOM_SERDES_RX_ADAPT_TRIGGER,

    /**
     * @brief Port serdes control 
     *
     * @type sai_pointer_t
     * @flags SET
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_SERDES_PARAMS_CFG,

    /* @brief Port serdes runtime control 
     *
     * @type sai_pointer_t 
     * @flags SET
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_SERDES_RUNTIME_PARAMS_CFG,

    /* @brief Port serdes diag parameters control 
     *
     * @type sai_pointer_t
     * @flags SET
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_SERDES_DIAG_PARAMS_CFG,            
   /**
     * @brief Defects get
     *
     * @type sai_pointer_t
     * @flags GET
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_DEFECTS,        

  /**
     * @brief PMON get
     *
     * @type sai_pointer_t
     * @flags GET
     * @default internal
     */
    SAI_PORT_ATTR_CUSTOM_PMON,            

/** End of custom range base */
    SAI_PORT_ATTR_CUSTOM_RANGE_DEFINED_END,

} sai_port_attr_custom_t;

/**
 * @brief List of custom SerDes port attributes
 */
typedef enum _sai_port_serdes_attr_custom_t
{

    /**
     * @brief Port serdes pin PRBS bit error rate.
     *
     * @type sai_pointer_t
     * @flags READ_ONLY
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_PRBS_BER = SAI_PORT_SERDES_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Port serdes pin adaptation objects.
     *
     * @type sai_pointer_t
     * @flags READ_ONLY
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_ADAPT_OBJECT,

    /**
     * @brief Trigger serdes adaptation
     *
     * 1 - Trigger serdes adaptation
     * 0 - No action.
     *
     * @type sai_u8_list_t u8list;
     * @flags SET
     * @default FALSE
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_RX_ADAPT_TRIGGER,

    /**
     * @brief TX error injection (one shot)
     *
     * 1 - TX error injection (one shot)
     * 0 - No action.
     *
     * @type sai_u8_list_t u8list
     * @flags SET
     * @default FALSE
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_PRBS_TX_ERR_INJECT,

    /**
     * @brief SerDes lane Rx polarity inversion
     *
     * 1 - Inverted
     * 0 - No change.
     *
     * @type sai_u8_list_t u8list;
     * @flags SET
     * @default FALSE
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_RX_INVERT_POLARITY,

    /**
     * @brief SerDes lane Tx polarity inversion
     *
     * 1 - Inverted
     * 0 - No change.
     *
     * @type bool
     * @flags SET
     * @default FALSE
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_TX_INVERT_POLARITY,

    /**
     * @brief serdes pin control 
     *
     * @type sai_pointer_t
     * @flags SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_CONFIG,

    /* @brief serdes pin runtime control 
     *
     * @type sai_pointer_t
     * @flags SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_RUNTIME_CONFIG,

    /* @brief serdes pin diag parameters control 
     *
     * @type sai_pointer_t
     * @flags SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_DIAG_CONFIG,        
    /**
     * @brief Serdes Pin Defects get
     *
     * @type sai_pointer_t
     * @flags GET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_CUSTOM_DEFECTS,        
    
    /** End of custom range base */
    SAI_PORT_SERDES_ATTR_CUSTOM_RANGE_DEFINED_END ,

} sai_port_serdes_attr_custom_t;


/* ###################################################################### */
/* #### End: PORT custom attributes #### */
/* ###################################################################### */

/* ###################################################################### */
/* #### Begin: ACL custom attributes #### */
/* ###################################################################### */

typedef enum _sai_acl_custom_range_type_t
{
    SAI_ACL_RANGE_CUSTOM_RANGE_START   = 0x10000000,
    
    /** MAC DA */
    SAI_ACL_RANGE_TYPE_MAC_DA = SAI_ACL_RANGE_CUSTOM_RANGE_START,

} sai_acl_custom_range_type_t;

typedef struct _sai_mac_custom_range_t
{
    sai_mac_t mac_da_start;
    sai_mac_t mac_da_end;
} sai_mac_custom_range_t;

typedef enum _sai_acl_table_attr_custom_t
{

    /**
     * @brief Macsec packet type
     *
     * @type uint32_t
     * @flags CREATE_ONLY
     * @default false
     */
    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_SEC_PACKET_TYPE = SAI_ACL_TABLE_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Macsec num of tags/labels
     *
     * @type bool
     * @flags CREATE_ONLY
     * @default false
     */
    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_SEC_NUM_TAGS,

    /**
     * @brief Macsec num of tags/labels
     *
     * @type bool
     * @flags CREATE_ONLY
     * @default false
     */
    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_MACSEC_PBB_SID,

    /**
     * @brief IPSEC SPI
     *
     * @type uint32_t
     * @flags CREATE_ONLY
     * @default false
     */
    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_IPSEC_SPI,


    /**
     * @brief IPSEC Ingress my tunnel table Id
     *
     * @type uint32_t 
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_IPSEC_MY_TUNNEL_TABLE_ID,    

    SAI_ACL_TABLE_ATTR_FIELD_CUSTOM_RANGE_DEFINED_END,

} sai_acl_table_attr_custom_t;

typedef enum _sai_acl_entry_attr_custom_t
{

    /**
     * @brief Set macsec packet type
     *
     * @type uint32_t
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_FIELD_CUSTOM_SEC_PACKET_TYPE = SAI_ACL_ENTRY_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Set macsec num of tags/labels
     *
     * @type uint32_t
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_FIELD_CUSTOM_SEC_NUM_TAGS,

    /**
     * @brief Set macsec pbb Service Instance Id value
     *
     * @type uint32_t 
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_FIELD_CUSTOM_MACSEC_PBB_SID,

    /**
     * @brief IPSEC SPI
     *
     * @type uint32_t 
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_FIELD_CUSTOM_IPSEC_SPI,

    /**
     * @brief IPSEC Ingress my tunnel table Id
     *
     * @type uint32_t 
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_FIELD_CUSTOM_IPSEC_MY_TUNNEL_TABLE_ID,

    /**
     * @brief Set global control packet macsec instance(slice) ID
     *
     * @type uint32_t
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_ACTION_SET_CUSTOM_SEC_INSTANCE_ID,


    /**
     * @brief mark packet as control packet 
     *
     * @type bool
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_ACTION_SET_CUSTOM_CONTROL_PACKET,

    /**
     * @brief vPort Index of the rule
     *
     * @type uint32_t
     * @flags CREATE
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_ACTION_SET_CUSTOM_IPSEC_SA_INDEX,
    
    /**
     * @brief Rule match counter
     *
     * @type uint64_t
     * @flags Read
     * @default 0
     */
    SAI_ACL_ENTRY_ATTR_CUSTOM_MATCH_COUNTER_READ,
    SAI_ACL_ENTRY_ATTR_CUSTOM_MATCH_COUNTER_READ_CLEAR,


    SAI_ACL_ENTRY_ATTR_CUSTOM_RANGE_DEFINED_END,

} sai_acl_entry_attr_custom_t;


/* ###################################################################### */
/* #### End: ACL custom attributes #### */
/* ###################################################################### */

/* ###################################################################### */
/* #### Begin: MACsec custom attributes #### */
/* ###################################################################### */

typedef enum _sai_macsec_attr_custom_t
{

    /**
     * @brief MACsec Instance Id (Slice Id)
     *
     * @type uint32_t
     * @flags SET
     * @default 0 
     */
    SAI_MACSEC_ATTR_CUSTOM_INSTANCE_ID = SAI_MACSEC_ATTR_CUSTOM_RANGE_START,

     /**
     * @brief TPID value used to identify packet S-tag2.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x9100
     */
    SAI_MACSEC_ATTR_CUSTOM_STAG2_TPID,

     /**
     * @brief TPID value used to identify packet S-tag3.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x9200
     */
    SAI_MACSEC_ATTR_CUSTOM_STAG3_TPID,

     /**
     * @brief MPLS header Ether Type.
     *
     * @type List of 4 sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x8847,0x8848,0 and 0
     */
    SAI_MACSEC_ATTR_CUSTOM_MPLS_HDR_ETHER_TYPE,

     /**
     * @brief PBB header BTAG Ether Type.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x88A8
     */
    SAI_MACSEC_ATTR_CUSTOM_PBB_HDR_BTAG_ETHER_TYPE,

     /**
     * @brief PBB header ITAG Ether Type.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x88E7
     */
    SAI_MACSEC_ATTR_CUSTOM_PBB_HDR_ITAG_ETHER_TYPE,

    SAI_MACSEC_ATTR_CUSTOM_RANGE_DEFINED_END
} sai_macsec_attr_custom_t;


typedef enum _sai_macsec_port_attr_custom_t
{
    /**
     * @brief Enable vlan tag parsing for S-tag2 TPID
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_STAG2_ENABLE = SAI_MACSEC_PORT_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Enable vlan tag parsing for S-tag3 TPID
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_STAG3_ENABLE,

    /**
     * @brief Enable vlan tag parsing for QINQ
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_QINQ_ENABLE,

    /**
     * @brief Enable MPLS header parsing
     *
     * @type bool list of 4
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_MPLS_HDR_ENABLE,


    /**
     * @brief Enable PBB header parsing
     *
     * @type bool list of 4
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_PBB_HDR_ENABLE,

     /**
     * @brief Mpls label select.
     *
     * @type uint32_t list of 2
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_MPLS_LABEL_SELECT,

    /**
     * @brief Mpls entropy label parsing
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_MPLS_PARSE_ELI,
    

    /**
     * @brief Sequence number threshold.
     *
     * @type uint64_t
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_SEQUENCE_NUM_THRESHOLD,


    /**
     * @brief should secure mode.
     * TRUE = should-secure mode. FALSE = must-secure mode
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default TRUE
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_SHOULD_SECURE,

    /**
     * @brief Indicates which Control Packet rules are enabled for this Channel.
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_CP_RULES_ENABLED,

    /**
     * @brief Bitmap to indicates which ethertype from the packet has to be used for control packet detection. 
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_CP_ETHER_TYPE_USED,
    /**
     * @brief Indicates which rules are enabled for secondary control packet detection.
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_SCP_RULES_ENABLED,

    /**
     * @brief Indicates which ethertype from the packet has to be used for secondary control packet detection. 
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_SCP_ETHER_TYPE_USED,    

    /**
     * @brief List of MACsec flow associated with this MACsec port object.
     *
     * @type sai_object_list_t
     * @flags READ_ONLY
     * @objects SAI_OBJECT_TYPE_MACSEC_FLOW
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_FLOW_LIST,

    /**
     * @brief End of custom range base
     */
    SAI_MACSEC_PORT_ATTR_CUSTOM_RANGE_DEFINED_END

} sai_macsec_port_attr_custom_t;


/**
 * @brief Attribute Id for SAI macsec flow attributes
 */
typedef enum _sai_macsec_flow_attr_custom_t
{

    /**
     * @brief MACsec port object to associated with this flow.
     *
     * @type sai_object   macsec port object
     * @flags CREATE
     * @objects SAI_OBJECT_TYPE_MACSEC_PORT
     */
    SAI_MACSEC_FLOW_ATTR_CUSTOM_MACSEC_PORT_ID = SAI_MACSEC_FLOW_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Unique 32-bit vPort key for this chnl_id + direction.
     *
     * @type uint32_t   
     * @flags CREATE
     * @default 0
     */
    SAI_MACSEC_FLOW_ATTR_CUSTOM_VPORT_KEY,    
    /**
     * @brief vport operating modes..
     *
     * @type uint32_t
     * @flags CREATE
     * @default 0
     */
    SAI_MACSEC_FLOW_ATTR_CUSTOM_VPORT_FLAGS,
    /**
     * @brief End of custom range base
     */
    SAI_MACSEC_FLOW_ATTR_CUSTOM_RANGE_DEFINED_END
} sai_macsec_flow_attr_custom_t;


/**
 * @brief Attribute Id for SAI MACsec SA custom
 */
typedef enum _sai_macsec_sa_attr_custom_t
{

    /**
     * @brief Maximum allowed packet size after Encryption (egress).
     *
     * @type  uint32_t
     * @flags CREATE_ONLY
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_MTU_SIZE = SAI_MACSEC_SA_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief macsec sa config flags
     *
     * @type  uint32  
     * @flags CREATE
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_CONFIG_FLAGS,

    /**
     * @brief macsec flow control flags
     *
     * @type  uint32  
     * 
     * For SET Operation, First we need to call the SC attribute set function and then we need to call the SA attribute set function .
     * 
     * For GET Operaton, First we need to read the any of SA attribute and then read the SC attribute.
     * 
     * @flags CREATE and SET
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_FLOW_CONTROL_FLAGS,

   /**
     * @brief macsec Confidentiality Offset
     * For SET Operation, First we need to call the SC attribute set function and then we need to call the SA attribute set function .
     * @type  uint32  
     * @flags CREATE and SET
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_FLOW_CONTROL_OFFSETS,

    /**
     * @brief Existing SA Id. The newly created SA will be chained to this SA.
     *
     * @type  sai_object_id_t SA Object Id  
     * @flags CREATE_ONLY
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_ACTIVE_SA_ID,

    /**
     * @brief New SA Id to manually switch to the new SA from the current active SA.
     *
     * @type  sai_object_id_t SA Object Id  
     * @flags Set
     * @default 0
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_SWITCH_SA_ID,

    /**
     * @brief End of custom range base
     */
    SAI_MACSEC_SA_ATTR_CUSTOM_RANGE_DEFINED_END
} sai_macsec_sa_attr_custom_t;

/* ====================================================================== */
/**
 * @brief CUSTOM MACsec flow counter IDs in sai_get_macsec_stats() call
 */
typedef enum _sai_macsec_flow_stat_custom_t
{
    /**
     * @brief Number of packets hitting sa not in use error. debug ONLY.
     */
    SAI_MACSEC_FLOW_STAT_CUSTOM_IN_SA_NOT_IN_USE_ERR = SAI_MACSEC_FLOW_STAT_IN_PKTS_OVERRUN + 1,
} sai_macsec_flow_stat_custom_t;

/**
 * @brief CUSTOM MACsec port counter IDs in sai_get_macsec_stats() call
 */
typedef enum _sai_macsec_port_stat_custom_t
{
    /**
     * @brief Number of packets received with multiple matching classification rules for MACsec processing
     */
    SAI_MACSEC_PORT_STAT_CUSTOM_MULTIPLE_RULE_MATCH = SAI_MACSEC_PORT_STAT_DATA_PKTS + 1,

    /**
     * @brief Number of packets dropped by the header parser as invalid for MACsec processing
     */
    SAI_MACSEC_PORT_STAT_CUSTOM_HEADER_PARSER_DROP,

    /**
     * @brief Number of packets that did not match any classification rules for MACsec processing
     */
    SAI_MACSEC_PORT_STAT_CUSTOM_RULE_MIS_MATCH,

    /**
     * @brief Number of packets marked with error packet indication before classification for MACsec processing
     */
    SAI_MACSEC_PORT_STAT_CUSTOM_IN_ERROR_PACKETS,
} sai_macsec_port_stat_custom_t;

/**
 * @brief CUSTOM MACsec flow counter IDs in sai_get_macsec_sa_stats() call.
 */
typedef enum _sai_macsec_sa_stat_custom_t
{
    SAI_MACSEC_SA_STAT_CMN_CUSTOM_RANGE_START   = 0x10000000,       // Common
    SAI_MACSEC_SA_STAT_IN_CUSTOM_RANGE_START    = 0x11000000,       // Ingress / IN
    SAI_MACSEC_SA_STAT_OUT_CUSTOM_RANGE_START   = 0x12000000,       // Egress  / OUT

    /* ====================================================================== */

    /**
     * @brief Number of packets hitting multiple TCAM entries
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKT_TCAM_HIT_MULTIPLE = SAI_MACSEC_SA_STAT_CMN_CUSTOM_RANGE_START,

    /**
     * @brief Number of packets dropped while parsing the header
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKT_DROP_HEADER_PARSE,

    /**
     * @brief Number of packets not hitting any TCAM entries
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKT_TCAM_MISS,

    /**
     * @brief Number of packets classified as control packets
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKTS_CTRL,

    /**
     * @brief Number of packets classified as data packets
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKTS_DATA,

    /**
     * @brief Number of packets dropped
     */
    SAI_MACSEC_SA_STAT_CUSTOM_PKTS_DROPPED,

    /* ====================================================================== */

    /**
     * @brief Number of packets running into transformation errors
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_TRANSFORM_ERROR = SAI_MACSEC_SA_STAT_IN_CUSTOM_RANGE_START,

    /**
     * @brief Number of control packets received
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_CTRL,

    /**
     * @brief Number of tagged control packets received
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_TAG_CTRL,

    /**
     * @brief Number of untagged packets received
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_UNTAGGED,

    /**
     * @brief Number of packets received without tag
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_NO_TAG,

    /**
     * @brief Number of packets received with invalid/bad tag
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_INVALID_TAG,

    /**
     * @brief Number of packets received without SCI
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_NO_SCI,

    /**
     * @brief Number of packets received with unknown/invalid SCI
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_PKTS_UNKNOWN_SCI,

    /**
     * @brief Ingress next packet number
     */
    SAI_MACSEC_SA_STAT_CUSTOM_IN_NEXT_PN,

    /* ====================================================================== */

    /**
     * @brief Number of packets running into transformation errors
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_PKTS_TRANSFORM_ERROR = SAI_MACSEC_SA_STAT_OUT_CUSTOM_RANGE_START,

    /**
     * @brief Number of control packets sent out
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_PKTS_CTRL,

    /**
     * @brief Number of untagged packets sent out
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_PKTS_UNTAGGED,

    /**
     * @brief Number of packets with packet length larger than max length configured
     * Valid for Egress, always returns 0 for Ingress.
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_PKTS_TOO_LONG,

      /**
     * @brief Number of packets that reached an unused SA
     * Valid for Egress, always returns 0 for Ingress.
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_PKTS_SA_NOT_IN_USE,

    /**
     * @brief Egress next packet number
     */
    SAI_MACSEC_SA_STAT_CUSTOM_OUT_NEXT_PN,

} sai_macsec_sa_stat_custom_t;


/* ###################################################################### */
/* #### End: MACsec custom attributes #### */
/* ###################################################################### */

/* ###################################################################### */
/* #### Begin: IPSec custom attributes #### */
/* ###################################################################### */

typedef enum _sai_ipsec_attr_custom_t
{

    /**
     * @brief IPsec direction
     *
     * @type sai_ipsec_direction_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     */
    SAI_IPSEC_ATTR_CUSTOM_DIRECTION = SAI_IPSEC_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief IPsec Instance Id (Slice Id)
     *
     * @type uint32_t
     * @flags SET
     * @default 0 
     */
    SAI_IPSEC_ATTR_CUSTOM_INSTANCE_ID,

    /**
     * @brief TPID value used to identify packet S-tag2.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x9100
     */
    SAI_IPSEC_ATTR_CUSTOM_STAG2_TPID,

    /**
     * @brief TPID value used to identify packet S-tag3.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x9200
     */
    SAI_IPSEC_ATTR_CUSTOM_STAG3_TPID,

    /**
     * @brief MPLS header Ether Type.
     *
     * @type List of 4 sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 0x8847,0x8848,0 and 0
     */
    SAI_IPSEC_ATTR_CUSTOM_MPLS_HDR_ETHER_TYPE,

    /**
     * @brief MAC-DA for comparision in IPsec header.
     *
     * @type sai_mac_t
     * @flags CREATE_AND_SET
     * @default 
     */
    SAI_IPSEC_ATTR_CUSTOM_MAC_DA,

    /**
     * @brief The IKE port value for comparison in IKE header.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 500
     */
    SAI_IPSEC_ATTR_CUSTOM_IKE_PORT,

    /**
     * @brief The NAT port value for comparison in NAT header.
     *
     * @type sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 4500
     */
    SAI_IPSEC_ATTR_CUSTOM_NAT_PORT,

    /**
     * @brief The port value for L4 Port comparison in L4 header.
     *
     * @type List of 4 sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 
     */
    SAI_IPSEC_ATTR_CUSTOM_L4_HDR_PORT,

    /**
     * @brief Provides the SA_TAG Ethertype value.
     * In Egress direction packet having this Ethertype value are classified for IPsec processing when channel is 
     * configured for IPSec.
     * In Ingress direction post IPsec packet processing this Ethertype value is inserted in packet post decryption 
     * if SA TAG is enabled for ingress SA.
     * 
     * @type List of 4 sai_uint16_t
     * @flags CREATE_AND_SET
     * @default 
     */

    SAI_IPSEC_ATTR_CUSTOM_SA_TAG_ETHER_TYPE,

    /**
     * @brief Vport list per slice per direction
     *
     * @type sai_uint32_t list
     * @flags GET
     * @default false
     */
    SAI_IPSEC_ATTR_CUSTOM_VPORT_LIST,

    /**
     * @brief Available Vport per slice per direction
     *
     * @type sai_uint32_t
     * @flags GET
     * @default false
     */
    SAI_IPSEC_ATTR_CUSTOM_AVAILABLE_VPORT,

   /**
     * @brief Tunnel Id to delete tunnel mapping entry. 
     * 
     *
     * @type sai_uint32_t
     * @flags SET
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_ATTR_CUSTOM_MY_TUNNEL_TABLE_DELETE,       

    SAI_IPSEC_ATTR_CUSTOM_RANGE_DEFINED_END
} sai_ipsec_attr_custom_t;



typedef enum _sai_ipsec_port_attr_custom_t
{

    /**
     * @brief IPsec direction
     *
     * @type sai_ipsec_direction_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_DIRECTION = SAI_IPSEC_PORT_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Enable vlan tag parsing for S-tag2 TPID
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_STAG2_ENABLE,

    /**
     * @brief Enable vlan tag parsing for S-tag3 TPID
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_STAG3_ENABLE,

    /**
     * @brief Enable vlan tag parsing for QINQ
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_QINQ_ENABLE,

    /**
     * @brief Enable MPLS header parsing
     *
     * @type bool list of 4
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_MPLS_HDR_ENABLE,

     /**
     * @brief Mpls label select.
     *
     * @type uint32_t list of 2
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_MPLS_LABEL_SELECT,

    /**
     * @brief Mpls entropy label parsing
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_MPLS_PARSE_ELI,
    

    /**
     * @brief Sequence number threshold.
     *
     * @type uint64_t
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_SEQUENCE_NUM_THRESHOLD,


    /**
     * @brief should secure mode.
     * TRUE = should-secure mode. FALSE = must-secure mode
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default true
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_SHOULD_SECURE,

    /**
     * @brief Indicates which Control Packet rules are enabled for this Channel.
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_CP_RULES_ENABLED,

    /**
     * @brief Bitmap to indicates which ethertype from the packet has to be used for control packet detection. 
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_CP_ETHER_TYPE_USED,
    /**
     * @brief Indicates which rules are enabled for secondary control packet detection.
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_SCP_RULES_ENABLED,

    /**
     * @brief Indicates which ethertype from the packet has to be used for secondary control packet detection. 
     *
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_SCP_ETHER_TYPE_USED,    

    /**
     * @brief ORed flags of ipsec_parse_flags for IPsec header parsing. 
     * 
     * @type uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_IPSEC_HDR_PARSE_FLAGS,

    /**
     * @brief Vport list per port per direction
     *
     * @type sai_uint32_t list
     * @flags GET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_VPORT_LIST,

    /**
     * @brief RuleId list per port per direction
     *
     * @type sai_uint32_t list
     * @flags GET
     * @default false
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_ACL_ENTRY_LIST,

    /**
     * @brief SA list per port per direction
     *
     * @type sai_uint32_t list
     * @flags GET
     * @default false
     */    
    SAI_IPSEC_PORT_ATTR_CUSTOM_SA_LIST,    

    /**
     * @brief Voprt Id to delete Vport. 
     * 
     *
     * @type sai_uint32_t
     * @flags SET
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_VPORT_DELETE,    

    /**
     * @brief End of custom range base
     */
    SAI_IPSEC_PORT_ATTR_CUSTOM_RANGE_DEFINED_END

} sai_ipsec_port_attr_custom_t;



/**
 * @brief Attribute Id for SAI IPSEC SA custom
 */
typedef enum _sai_ipsec_sa_attr_custom_t
{

    /**
     * @brief Unique 32-bit vPort key for this chnl_id + direction.
     *
     * @type sai_uint32_t   
     * @flags CREATE
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_VPORT_KEY = SAI_IPSEC_SA_ATTR_CUSTOM_RANGE_START,  

    /**
     * @brief AN value (2-bit) for SA.
     * The value must be distinct from other Secure Associations for the same vPort.
     *
     * @type sai_uint8_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_AN,  

    /**
     * @brief Maximum allowed packet size after Encryption (egress).
     *
     * @type  uint32_t
     * @flags CREATE_ONLY
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_EGRESS
     * @default 0
     * 
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_MTU_SIZE,

    /**
     * @brief ipsec sa config flags
     *
     * @type  uint32  
     * @flags CREATE
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_CONFIG_FLAGS,

    /**
     * @brief ipsec flow control flags
     *
     * @type  uint32  
     * 
     * @flags CREATE and SET
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_FLOW_CONTROL_FLAGS,

   /**
     * @brief ipsec Confidentiality Offset
     * @type  uint32  
     * @flags CREATE and SET
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_FLOW_CONTROL_OFFSETS,

    /**
     * @brief Existing SA Id. The newly created SA will be chained to this SA.
     *
     * @type  sai_object_id_t SA Object Id  
     * @flags CREATE_ONLY
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_ACTIVE_SA_ID,

    /**
     * @brief New SA Id to manually switch to the new SA from the current active SA.
     *
     * @type  sai_object_id_t SA Object Id  
     * @flags Set
     * @default 0
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_SWITCH_SA_ID,

    /**
     * @brief SA local IP address mask for tunnel termination.
     *
     * @type sai_ip_address_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_TERM_DST_IP_MASK,

    /**
     * @brief Vlan Id mask for tunnel termination.
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @isvlan true
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS and SAI_IPSEC_SA_ATTR_TERM_VLAN_ID_ENABLE == true
     */    
    SAI_IPSEC_SA_ATTR_CUSTOM_TERM_VLAN_ID_MASK,

    /**
     * @brief Match MPLS label for tunnel termination.
     *
     * @type bool
     * @flags CREATE_ONLY
     * @default false
     * @validonly SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */    
    SAI_IPSEC_SA_ATTR_CUSTOM_TERM_MPLS_LABEL_ENABLE,

    /**
     * @brief MPLS LABEL for tunnel termination.
     *
     * @type sai_uint32_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @isvlan true
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS and SAI_IPSEC_SA_ATTR_TERM_VLAN_ID_ENABLE == true
     */      
    SAI_IPSEC_SA_ATTR_CUSTOM_TERM_MPLS_LABEL,

    /**
     * @brief MPLS LABEL mask for tunnel termination.
     *
     * @type sai_uint32_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @isvlan true
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS and SAI_IPSEC_SA_ATTR_TERM_VLAN_ID_ENABLE == true
     */          
    SAI_IPSEC_SA_ATTR_CUSTOM_TERM_MPLS_LABEL_MASK,

   /**
     * @brief Tunnel Id for new tunnel mapping entry. The tunnel mapping
     *  entry can be shared between chnl_ids in a direction per slice.
     *  Use SAI_IPSEC_SA_ATTR_CUSTOM_MY_TUNNEL_TABLE_CHNL_UPDATE to add or remove the chnl_id to tunnel-id relation.
     * 
     *
     * @type sai_uint32_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_MY_TUNNEL_TABLE_ID,    


    /**
     * @brief Reads a Tunnel Mapping entry
     *
     * @type sai_pointer_t
     * @flags READ_ONLY
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_MY_TUNNEL_TABLE_READ,    

    /**
     * @brief Updates a Tunnel mapping entry for a channel
     *
     * @type sai_pointer_t
     * @flags READ_ONLY
     * @condition SAI_IPSEC_SA_ATTR_IPSEC_DIRECTION == SAI_IPSEC_DIRECTION_INGRESS
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_MY_TUNNEL_TABLE_CHNL_UPDATE,       

    /**
     * @brief Reads vport stats
     *
     * @type sai_pointer_t
     * @flags READ_ONLY
     * 
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_VPORT_STATS_READ,
    SAI_IPSEC_SA_ATTR_CUSTOM_VPORT_STATS_READ_CLEAR,
    /**
     * @brief End of custom range base
     */
    SAI_IPSEC_SA_ATTR_CUSTOM_RANGE_DEFINED_END
} sai_ipsec_sa_attr_custom_t;

/* ====================================================================== */

typedef enum _sai_ipsec_port_stat_custom_t
{
    /**
     * @brief Number of packets received with multiple matching classification rules for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_TX_CUSTOM_MULTIPLE_RULE_MATCH = SAI_IPSEC_PORT_STAT_RX_NON_IPSEC_PKTS + 1,

    /**
     * @brief Number of packets dropped by the header parser as invalid for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_TX_CUSTOM_HEADER_PARSER_DROP,

    /**
     * @brief Number of packets that did not match any classification rules for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_TX_CUSTOM_RULE_MIS_MATCH,

    /**
     * @brief Number of packets marked with error packet indication before classification for IPSEC processing
     */
    SAI_IPSEC_PORT_STAT_TX_CUSTOM_DROPPED_PACKETS,

    /**
     * @brief Number of packets received with multiple matching classification rules for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_RX_CUSTOM_MULTIPLE_RULE_MATCH,

    /**
     * @brief Number of packets dropped by the header parser as invalid for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_RX_CUSTOM_HEADER_PARSER_DROP,

    /**
     * @brief Number of packets that did not match any classification rules for IPsec processing
     */
    SAI_IPSEC_PORT_STAT_RX_CUSTOM_RULE_MIS_MATCH,

    /**
     * @brief Number of packets marked with error packet indication before classification for IPSEC processing
     */
    SAI_IPSEC_PORT_STAT_RX_CUSTOM_DROPPED_PACKETS,

    /**
     * @brief  Number of packets that did not match any tunnel. Ingress IPsec ONLY
     */
    SAI_IPSEC_PORT_STAT_RX_CUSTOM_IN_TUNNEL_MISMATCH,

} sai_ipsec_port_stat_custom_t;

typedef enum _sai_ipsec_sa_stat_custom_t
{
    SAI_IPSEC_SA_STAT_CMN_CUSTOM_RANGE_START   = 0x10000000,       // Common
    SAI_IPSEC_SA_STAT_IN_CUSTOM_RANGE_START    = 0x11000000,       // Ingress / IN
    SAI_IPSEC_SA_STAT_OUT_CUSTOM_RANGE_START   = 0x12000000,       // Egress  / OUT

    /* ====================================================================== */


    /* ====================================================================== */


    /* ====================================================================== */

    /**
     * @brief < Number of packets with packet length larger than max length configured
     */
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_TOO_LONG = SAI_IPSEC_SA_STAT_CMN_CUSTOM_RANGE_START,

    /**
     * @brief  Number of packets that reached an unused SA
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_SA_NOT_IN_USE,

    /**
     * @brief  Number of packets that were invalid frames for controlled port
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_INVALID,

    /**
     * @brief  Number of controlled port packets received at uncontrolled port
     */ 

    SAI_IPSEC_SA_STAT_CUSTOM_PROTECTED_PKTS_VALID,

    /**
     * @brief  Number of uncontrolled port packets that reached not in use SA
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_NOT_USING_SA,

    /**
     * @brief  Number of controlled port packets that reached upto SA
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_UNUSED_SA,

    /**
     * @brief  Number of octets of User Data recovered from rx frames that were integrity protected but not encrypted
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_PKTS_OCTECTS_VALIDATED,

    /**
     * @brief  tunnel statistics counters
     */ 
    SAI_IPSEC_SA_STAT_CUSTOM_TUNNEL_ENTRY_PKTS,    

    /* ====================================================================== */

} sai_ipsec_sa_stat_custom_t;

/* ###################################################################### */
/* #### End: IPSec custom attributes #### */
/* ###################################################################### */

#endif
