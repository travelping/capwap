%% Copyright (C) 2013-2017, Travelping GmbH <info@travelping.com>

%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Affero General Public License as published by
%% the Free Software Foundation, either version 3 of the License, or
%% (at your option) any later version.

%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%% GNU Affero General Public License for more details.

%% You should have received a copy of the GNU Affero General Public License
%% along with this program.  If not, see <http://www.gnu.org/licenses/>.

%% Information Element IDs
-define(WLAN_EID_SSID, 0).
-define(WLAN_EID_SUPP_RATES, 1).
-define(WLAN_EID_FH_PARAMS, 2).
-define(WLAN_EID_DS_PARAMS, 3).
-define(WLAN_EID_CF_PARAMS, 4).
-define(WLAN_EID_TIM, 5).
-define(WLAN_EID_IBSS_PARAMS, 6).
-define(WLAN_EID_COUNTRY, 7).
-define(WLAN_EID_BSS_LOAD, 11).
-define(WLAN_EID_CHALLENGE, 16).
%% EIDs defined by IEEE 802.11h - START
-define(WLAN_EID_PWR_CONSTRAINT, 32).
-define(WLAN_EID_PWR_CAPABILITY, 33).
-define(WLAN_EID_TPC_REQUEST, 34).
-define(WLAN_EID_TPC_REPORT, 35).
-define(WLAN_EID_SUPPORTED_CHANNELS, 36).
-define(WLAN_EID_CHANNEL_SWITCH, 37).
-define(WLAN_EID_MEASURE_REQUEST, 38).
-define(WLAN_EID_MEASURE_REPORT, 39).
-define(WLAN_EID_QUITE, 40).
-define(WLAN_EID_IBSS_DFS, 41).
%% EIDs defined by IEEE 802.11h - END
-define(WLAN_EID_ERP_INFO, 42).
-define(WLAN_EID_HT_CAP, 45).
-define(WLAN_EID_QOS, 46).
-define(WLAN_EID_RSN, 48).
-define(WLAN_EID_EXT_SUPP_RATES, 50).
-define(WLAN_EID_NEIGHBOR_REPORT, 52).
-define(WLAN_EID_MOBILITY_DOMAIN, 54).
-define(WLAN_EID_FAST_BSS_TRANSITION, 55).
-define(WLAN_EID_TIMEOUT_INTERVAL, 56).
-define(WLAN_EID_RIC_DATA, 57).
-define(WLAN_EID_SUPPORTED_OPERATING_CLASSES, 59).
-define(WLAN_EID_EXT_CHANSWITCH_ANN, 60).
-define(WLAN_EID_HT_OPERATION, 61).
-define(WLAN_EID_SECONDARY_CHANNEL_OFFSET, 62).
-define(WLAN_EID_WAPI, 68).
-define(WLAN_EID_TIME_ADVERTISEMENT, 69).
-define(WLAN_EID_RRM_ENABLED_CAPABILITIES, 70).
-define(WLAN_EID_20_40_BSS_COEXISTENCE, 72).
-define(WLAN_EID_20_40_BSS_INTOLERANT, 73).
-define(WLAN_EID_OVERLAPPING_BSS_SCAN_PARAMS, 74).
-define(WLAN_EID_MMIE, 76).
-define(WLAN_EID_SSID_LIST, 84).
-define(WLAN_EID_BSS_MAX_IDLE_PERIOD, 90).
-define(WLAN_EID_TFS_REQ, 91).
-define(WLAN_EID_TFS_RESP, 92).
-define(WLAN_EID_WNMSLEEP, 93).
-define(WLAN_EID_TIME_ZONE, 98).
-define(WLAN_EID_LINK_ID, 101).
-define(WLAN_EID_INTERWORKING, 107).
-define(WLAN_EID_ADV_PROTO, 108).
-define(WLAN_EID_QOS_MAP_SET, 110).
-define(WLAN_EID_ROAMING_CONSORTIUM, 111).
-define(WLAN_EID_MESH_CONFIG, 113).
-define(WLAN_EID_MESH_ID, 114).
-define(WLAN_EID_PEER_MGMT, 117).
-define(WLAN_EID_EXT_CAPAB, 127).
-define(WLAN_EID_AMPE, 139).
-define(WLAN_EID_MIC, 140).
-define(WLAN_EID_CCKM, 156).
-define(WLAN_EID_MULTI_BAND, 158).
-define(WLAN_EID_SESSION_TRANSITION, 164).
-define(WLAN_EID_VHT_CAP, 191).
-define(WLAN_EID_VHT_OPERATION, 192).
-define(WLAN_EID_VHT_EXTENDED_BSS_LOAD, 193).
-define(WLAN_EID_VHT_WIDE_BW_CHSWITCH,  194).
-define(WLAN_EID_VHT_TRANSMIT_POWER_ENVELOPE, 195).
-define(WLAN_EID_VHT_CHANNEL_SWITCH_WRAPPER, 196).
-define(WLAN_EID_VHT_AID, 197).
-define(WLAN_EID_VHT_QUIET_CHANNEL, 198).
-define(WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION, 199).
-define(WLAN_EID_VENDOR_SPECIFIC, 221).


-define(IEEE_802_1_OUI, <<16#00, 16#0F, 16#AC>>).
-define(IEEE_802_1_CIPHER_SUITE_AES, <<?IEEE_802_1_OUI/binary, 4>>).

%% 802.11 Key Management
-define(IEEE_802_1_AKM_WPA, <<?IEEE_802_1_OUI/binary, 1>>).
-define(IEEE_802_1_AKM_PSK, <<?IEEE_802_1_OUI/binary, 2>>).
-define(IEEE_802_1_AKM_FT_WPA, <<?IEEE_802_1_OUI/binary, 3>>).
-define(IEEE_802_1_AKM_FT_PSK, <<?IEEE_802_1_OUI/binary, 4>>).

%% 802.11 Action Category
-define(WLAN_ACTION_FT, 6).
