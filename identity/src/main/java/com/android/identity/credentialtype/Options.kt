/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.credentialtype

/**
 * Object containing reusable lists of [IntegerOption] or [StringOption]
 */
object Options {
    /**
     * ISO/IEC 5218 values for sex/gender
     */
    val SEX_ISO_IEC_5218: List<IntegerOption> = listOf(
        IntegerOption(null, "(not set)"),
        IntegerOption(0, "Not known"),
        IntegerOption(1, "Male"),
        IntegerOption(2, "Female"),
        IntegerOption(9, "Not applicable")
    )

    /**
     * Values for name suffix in the AAMVA namespace
     */
    val AAMVA_NAME_SUFFIX = listOf(
        StringOption(null, "(not set)"),
        StringOption("JR", "Junior"),
        StringOption("SR", "Senior"),
        StringOption("1ST", "First"),
        StringOption("2ND", "Second"),
        StringOption("3RD", "Third"),
        StringOption("4TH", "Fourth"),
        StringOption("5TH", "Fifth"),
        StringOption("6TH", "Sixth"),
        StringOption("7TH", "Seventh"),
        StringOption("8TH", "Eighth"),
        StringOption("9TH", "Ninth")
    )

    /**
     * ISO 3166-1 Alpha 2 values for Countries
     */
    val COUNTRY_ISO_3166_1_ALPHA_2 = listOf(
        StringOption(null, "(not set)"),
        StringOption("AD", "Andorra"),
        StringOption("AE", "United Arab Emirates"),
        StringOption("AF", "Afghanistan"),
        StringOption("AG", "Antigua and Barbuda"),
        StringOption("AI", "Anguilla"),
        StringOption("AL", "Albania"),
        StringOption("AM", "Armenia"),
        StringOption("AO", "Angola"),
        StringOption("AQ", "Antarctica"),
        StringOption("AR", "Argentina"),
        StringOption("AS", "American Samoa"),
        StringOption("AT", "Austria"),
        StringOption("AU", "Australia"),
        StringOption("AW", "Aruba"),
        StringOption("AX", "Åland Islands"),
        StringOption("AZ", "Azerbaijan"),
        StringOption("BA", "Bosnia and Herzegovina"),
        StringOption("BB", "Barbados"),
        StringOption("BD", "Bangladesh"),
        StringOption("BE", "Belgium"),
        StringOption("BF", "Burkina Faso"),
        StringOption("BG", "Bulgaria"),
        StringOption("BH", "Bahrain"),
        StringOption("BI", "Burundi"),
        StringOption("BJ", "Benin"),
        StringOption("BL", "Saint Barthélemy"),
        StringOption("BM", "Bermuda"),
        StringOption("BN", "Brunei Darussalam"),
        StringOption("BO", "Bolivia (Plurinational State of)"),
        StringOption("BQ", "Bonaire, Sint Eustatius and Saba"),
        StringOption("BR", "Brazil"),
        StringOption("BS", "Bahamas"),
        StringOption("BT", "Bhutan"),
        StringOption("BV", "Bouvet Island"),
        StringOption("BW", "Botswana"),
        StringOption("BY", "Belarus"),
        StringOption("BZ", "Belize"),
        StringOption("CA", "Canada"),
        StringOption("CC", "Cocos (Keeling) Islands"),
        StringOption("CD", "Congo, Democratic Republic of the"),
        StringOption("CF", "Central African Republic"),
        StringOption("CG", "Congo"),
        StringOption("CH", "Switzerland"),
        StringOption("CI", "Côte d'Ivoire"),
        StringOption("CK", "Cook Islands"),
        StringOption("CL", "Chile"),
        StringOption("CM", "Cameroon"),
        StringOption("CN", "China"),
        StringOption("CO", "Colombia"),
        StringOption("CR", "Costa Rica"),
        StringOption("CU", "Cuba"),
        StringOption("CV", "Cabo Verde"),
        StringOption("CW", "Curaçao"),
        StringOption("CX", "Christmas Island"),
        StringOption("CY", "Cyprus"),
        StringOption("CZ", "Czechia"),
        StringOption("DE", "Germany"),
        StringOption("DJ", "Djibouti"),
        StringOption("DK", "Denmark"),
        StringOption("DM", "Dominica"),
        StringOption("DO", "Dominican Republic"),
        StringOption("DZ", "Algeria"),
        StringOption("EC", "Ecuador"),
        StringOption("EE", "Estonia"),
        StringOption("EG", "Egypt"),
        StringOption("EH", "Western Sahara"),
        StringOption("ER", "Eritrea"),
        StringOption("ES", "Spain"),
        StringOption("ET", "Ethiopia"),
        StringOption("FI", "Finland"),
        StringOption("FJ", "Fiji"),
        StringOption("FK", "Falkland Islands (Malvinas)"),
        StringOption("FM", "Micronesia (Federated States of)"),
        StringOption("FO", "Faroe Islands"),
        StringOption("FR", "France"),
        StringOption("GA", "Gabon"),
        StringOption("GB", "United Kingdom of Great Britain and Northern Ireland"),
        StringOption("GD", "Grenada"),
        StringOption("GE", "Georgia"),
        StringOption("GF", "French Guiana"),
        StringOption("GG", "Guernsey"),
        StringOption("GH", "Ghana"),
        StringOption("GI", "Gibraltar"),
        StringOption("GL", "Greenland"),
        StringOption("GM", "Gambia"),
        StringOption("GN", "Guinea"),
        StringOption("GP", "Guadeloupe"),
        StringOption("GQ", "Equatorial Guinea"),
        StringOption("GR", "Greece"),
        StringOption("GS", "South Georgia and the South Sandwich Islands"),
        StringOption("GT", "Guatemala"),
        StringOption("GU", "Guam"),
        StringOption("GW", "Guinea-Bissau"),
        StringOption("GY", "Guyana"),
        StringOption("HK", "Hong Kong"),
        StringOption("HM", "Heard Island and McDonald Islands"),
        StringOption("HN", "Honduras"),
        StringOption("HR", "Croatia"),
        StringOption("HT", "Haiti"),
        StringOption("HU", "Hungary"),
        StringOption("ID", "Indonesia"),
        StringOption("IE", "Ireland"),
        StringOption("IL", "Israel"),
        StringOption("IM", "Isle of Man"),
        StringOption("IN", "India"),
        StringOption("IO", "British Indian Ocean Territory"),
        StringOption("IQ", "Iraq"),
        StringOption("IR", "Iran (Islamic Republic of)"),
        StringOption("IS", "Iceland"),
        StringOption("IT", "Italy"),
        StringOption("JE", "Jersey"),
        StringOption("JM", "Jamaica"),
        StringOption("JO", "Jordan"),
        StringOption("JP", "Japan"),
        StringOption("KE", "Kenya"),
        StringOption("KG", "Kyrgyzstan"),
        StringOption("KH", "Cambodia"),
        StringOption("KI", "Kiribati"),
        StringOption("KM", "Comoros"),
        StringOption("KN", "Saint Kitts and Nevis"),
        StringOption("KP", "Korea (Democratic People's Republic of)"),
        StringOption("KR", "Korea, Republic of"),
        StringOption("KW", "Kuwait"),
        StringOption("KY", "Cayman Islands"),
        StringOption("KZ", "Kazakhstan"),
        StringOption("LA", "Lao People's Democratic Republic"),
        StringOption("LB", "Lebanon"),
        StringOption("LC", "Saint Lucia"),
        StringOption("LI", "Liechtenstein"),
        StringOption("LK", "Sri Lanka"),
        StringOption("LR", "Liberia"),
        StringOption("LS", "Lesotho"),
        StringOption("LT", "Lithuania"),
        StringOption("LU", "Luxembourg"),
        StringOption("LV", "Latvia"),
        StringOption("LY", "Libya"),
        StringOption("MA", "Morocco"),
        StringOption("MC", "Monaco"),
        StringOption("MD", "Moldova, Republic of"),
        StringOption("ME", "Montenegro"),
        StringOption("MF", "Saint Martin (French part)"),
        StringOption("MG", "Madagascar"),
        StringOption("MH", "Marshall Islands"),
        StringOption("MK", "North Macedonia"),
        StringOption("ML", "Mali"),
        StringOption("MM", "Myanmar"),
        StringOption("MN", "Mongolia"),
        StringOption("MO", "Macao"),
        StringOption("MP", "Northern Mariana Islands"),
        StringOption("MQ", "Martinique"),
        StringOption("MR", "Mauritania"),
        StringOption("MS", "Montserrat"),
        StringOption("MT", "Malta"),
        StringOption("MU", "Mauritius"),
        StringOption("MV", "Maldives"),
        StringOption("MW", "Malawi"),
        StringOption("MX", "Mexico"),
        StringOption("MY", "Malaysia"),
        StringOption("MZ", "Mozambique"),
        StringOption("NA", "Namibia"),
        StringOption("NC", "New Caledonia"),
        StringOption("NE", "Niger"),
        StringOption("NF", "Norfolk Island"),
        StringOption("NG", "Nigeria"),
        StringOption("NI", "Nicaragua"),
        StringOption("NL", "Netherlands, Kingdom of the"),
        StringOption("NO", "Norway"),
        StringOption("NP", "Nepal"),
        StringOption("NR", "Nauru"),
        StringOption("NU", "Niue"),
        StringOption("NZ", "New Zealand"),
        StringOption("OM", "Oman"),
        StringOption("PA", "Panama"),
        StringOption("PE", "Peru"),
        StringOption("PF", "French Polynesia"),
        StringOption("PG", "Papua New Guinea"),
        StringOption("PH", "Philippines"),
        StringOption("PK", "Pakistan"),
        StringOption("PL", "Poland"),
        StringOption("PM", "Saint Pierre and Miquelon"),
        StringOption("PN", "Pitcairn"),
        StringOption("PR", "Puerto Rico"),
        StringOption("PS", "Palestine, State of"),
        StringOption("PT", "Portugal"),
        StringOption("PW", "Palau"),
        StringOption("PY", "Paraguay"),
        StringOption("QA", "Qatar"),
        StringOption("RE", "Réunion"),
        StringOption("RO", "Romania"),
        StringOption("RS", "Serbia"),
        StringOption("RU", "Russian Federation"),
        StringOption("RW", "Rwanda"),
        StringOption("SA", "Saudi Arabia"),
        StringOption("SB", "Solomon Islands"),
        StringOption("SC", "Seychelles"),
        StringOption("SD", "Sudan"),
        StringOption("SE", "Sweden"),
        StringOption("SG", "Singapore"),
        StringOption("SH", "Saint Helena, Ascension and Tristan da Cunha"),
        StringOption("SI", "Slovenia"),
        StringOption("SJ", "Svalbard and Jan Mayen"),
        StringOption("SK", "Slovakia"),
        StringOption("SL", "Sierra Leone"),
        StringOption("SM", "San Marino"),
        StringOption("SN", "Senegal"),
        StringOption("SO", "Somalia"),
        StringOption("SR", "Suriname"),
        StringOption("SS", "South Sudan"),
        StringOption("ST", "Sao Tome and Principe"),
        StringOption("SV", "El Salvador"),
        StringOption("SX", "Sint Maarten (Dutch part)"),
        StringOption("SY", "Syrian Arab Republic"),
        StringOption("SZ", "Eswatini"),
        StringOption("TC", "Turks and Caicos Islands"),
        StringOption("TD", "Chad"),
        StringOption("TF", "French Southern Territories"),
        StringOption("TG", "Togo"),
        StringOption("TH", "Thailand"),
        StringOption("TJ", "Tajikistan"),
        StringOption("TK", "Tokelau"),
        StringOption("TL", "Timor-Leste"),
        StringOption("TM", "Turkmenistan"),
        StringOption("TN", "Tunisia"),
        StringOption("TO", "Tonga"),
        StringOption("TR", "Türkiye"),
        StringOption("TT", "Trinidad and Tobago"),
        StringOption("TV", "Tuvalu"),
        StringOption("TW", "Taiwan, Province of China"),
        StringOption("TZ", "Tanzania, United Republic of"),
        StringOption("UA", "Ukraine"),
        StringOption("UG", "Uganda"),
        StringOption("UM", "United States Minor Outlying Islands"),
        StringOption("US", "United States of America"),
        StringOption("UY", "Uruguay"),
        StringOption("UZ", "Uzbekistan"),
        StringOption("VA", "Holy See"),
        StringOption("VC", "Saint Vincent and the Grenadines"),
        StringOption("VE", "Venezuela (Bolivarian Republic of)"),
        StringOption("VG", "Virgin Islands (British)"),
        StringOption("VI", "Virgin Islands (U.S.)"),
        StringOption("VN", "Viet Nam"),
        StringOption("VU", "Vanuatu"),
        StringOption("WF", "Wallis and Futuna"),
        StringOption("WS", "Samoa"),
        StringOption("YE", "Yemen"),
        StringOption("YT", "Mayotte"),
        StringOption("ZA", "South Africa"),
        StringOption("ZM", "Zambia"),
        StringOption("ZW", "Zimbabwe"),
    )

    /**
     * Values for distinguishing sign according to ISO/IEC 18013-1 Annex F
     */
    val DISTINGUISHING_SIGN_ISO_IEC_18013_1_ANNEX_F = listOf(
        StringOption("AFG", "Afghanistan"),
        StringOption("AL", "Albania"),
        StringOption("GBA", "Alderney"),
        StringOption("DZ", "Algeria"),
        StringOption("AND", "Andorra"),
        StringOption("RA", "Argentina"),
        StringOption("AM", "Armenia"),
        StringOption("AUS", "Australia"),
        StringOption("A", "Austria"),
        StringOption("AZ", "Azerbaijan"),
        StringOption("BS", "Bahamas"),
        StringOption("BRN", "Bahrain"),
        StringOption("BD", "Bangladesh"),
        StringOption("BDS", "Barbados"),
        StringOption("BY", "Belarus"),
        StringOption("B", "Belgium"),
        StringOption("BH", "Belize (former British Honduras)"),
        StringOption("DY", "Benin"),
        StringOption("BOL", "Bolivia"),
        StringOption("BIH", "Bosnia and Herzegovina"),
        StringOption("BW", "Botswana"),
        StringOption("BR", "Brazil"),
        StringOption("BRU", "Brunei"),
        StringOption("BG", "Bulgaria"),
        StringOption("BF", "Burkina Faso"),
        StringOption("RU", "Burundi"),
        StringOption("K", "Cambodia"),
        StringOption("CAM", "Cameroon"),
        StringOption("CDN", "Canada"),
        StringOption("RCA", "Central African Republic"),
        StringOption("TCH", "Chad (TCH)"),
        StringOption("TD", "Chad (TD)"),
        StringOption("RCH", "Chile"),
        StringOption("RC", "China (Republic of)"),
        StringOption("CO", "Colombia"),
        StringOption("RCB", "Congo"),
        StringOption("CR", "Costa Rica"),
        StringOption("CI", "Côte d’Ivoire"),
        StringOption("HR", "Croatia"),
        StringOption("CU", "Cuba"),
        StringOption("CY", "Cyprus"),
        StringOption("CZ", "Czech Republic"),
        StringOption("ZRE", "Democratic Republic of the Congo"),
        StringOption("DK", "Denmark"),
        StringOption("WD", "Dominica (Windward Islands)"),
        StringOption("DOM", "Dominican Republic"),
        StringOption("EC", "Ecuador"),
        StringOption("ET", "Egypt"),
        StringOption("ES", "El Salvador"),
        StringOption("ER", "Eritrea"),
        StringOption("EST", "Estonia"),
        StringOption("ETH", "Ethiopia"),
        StringOption("FO", "Faroe Islands"),
        StringOption("FJI", "Fiji"),
        StringOption("FIN", "Finland"),
        StringOption("F", "France"),
        StringOption("G", "Gabon"),
        StringOption("WAG", "Gambia"),
        StringOption("GE", "Georgia"),
        StringOption("D", "Germany"),
        StringOption("GH", "Ghana"),
        StringOption("GBZ", "Gibraltar"),
        StringOption("GR", "Greece"),
        StringOption("WG", "Grenada (Windward Islands)"),
        StringOption("GCA", "Guatemala"),
        StringOption("GBG", "Guernsey"),
        StringOption("RG", "Guinea"),
        StringOption("GUY", "Guyana"),
        StringOption("RH", "Haiti"),
        StringOption("V", "Holy See"),
        StringOption("H", "Hungary"),
        StringOption("IS", "Iceland"),
        StringOption("IND", "India"),
        StringOption("RI", "Indonesia"),
        StringOption("IR", "Iran (Islamic Republic of)"),
        StringOption("IRQ", "Iraq"),
        StringOption("IRL", "Ireland"),
        StringOption("GBM", "Isle of Man"),
        StringOption("IL", "Israel"),
        StringOption("I", "Italy"),
        StringOption("JA", "Jamaica"),
        StringOption("J", "Japan"),
        StringOption("GBJ", "Jersey"),
        StringOption("HKJ", "Jordan"),
        StringOption("KZ", "Kazakhstan"),
        StringOption("EAK", "Kenya"),
        StringOption("KWT", "Kuwait"),
        StringOption("KG", "Kyrgyzstan"),
        StringOption("LAO", "Lao People’s Democratic Republic"),
        StringOption("LV", "Latvia"),
        StringOption("RL", "Lebanon"),
        StringOption("LS", "Lesotho"),
        StringOption("LB", "Liberia"),
        StringOption("LAR", "Libyan Arab Jamahiriya"),
        StringOption("FL", "Liechtenstein"),
        StringOption("LT", "Lithuania"),
        StringOption("L", "Luxembourg"),
        StringOption("RM", "Madagascar"),
        StringOption("MW", "Malawi"),
        StringOption("MAL", "Malaysia"),
        StringOption("RMM", "Mali"),
        StringOption("M", "Malta"),
        StringOption("RIM", "Mauritania"),
        StringOption("MS", "Mauritius"),
        StringOption("MEX", "Mexico"),
        StringOption("MD", "Moldova"),
        StringOption("MC", "Monaco"),
        StringOption("MGL", "Mongolia"),
        StringOption("MNE", "Montenegro"),
        StringOption("MA", "Morocco"),
        StringOption("MOC", "Mozambique"),
        StringOption("BUR", "Myanmar"),
        StringOption("SLO", "NA Slovenia"),
        StringOption("NAM", "Namibia"),
        StringOption("NAU", "Nauru"),
        StringOption("NEP", "Nepal"),
        StringOption("NL", "Netherlands"),
        StringOption("NA", "Netherlands Antilles"),
        StringOption("NZ", "New Zealand"),
        StringOption("NIC", "Nicaragua"),
        StringOption("RN", "Niger"),
        StringOption("WAN", "Nigeria"),
        StringOption("N", "Norway"),
        StringOption("PK", "Pakistan"),
        StringOption("PA", "Panama"),
        StringOption("PNG", "Papua New Guinea"),
        StringOption("PY", "Paraguay"),
        StringOption("PE", "Peru"),
        StringOption("RP", "Philippines"),
        StringOption("SD", "PNG Swaziland"),
        StringOption("PL", "Poland"),
        StringOption("P", "Portugal"),
        StringOption("Q", "Qatar"),
        StringOption("ROK", "Republic of Korea"),
        StringOption("RO", "Romania"),
        StringOption("RUS", "Russian Federation"),
        StringOption("RWA", "Rwanda"),
        StringOption("WS", "Samoa"),
        StringOption("RSM", "San Marino"),
        StringOption("SA", "Saudi Arabia"),
        StringOption("SN", "Senegal"),
        StringOption("SRB", "Serbia"),
        StringOption("SY", "Seychelles"),
        StringOption("WAL", "Sierra Leone"),
        StringOption("SGP", "Singapore"),
        StringOption("SK", "Slovakia"),
        StringOption("SO", "Somalia"),
        StringOption("ZA", "South Africa"),
        StringOption("E", "Spain (incl African localities and provinces)"),
        StringOption("CL", "Sri Lanka"),
        StringOption("WL", "St Lucia (Windward Islands)"),
        StringOption("WV", "St Vincent and the Grenadines (Windward Islands)"),
        StringOption("SUD", "Sudan"),
        StringOption("SME", "Suriname"),
        StringOption("S", "Sweden"),
        StringOption("CH", "Switzerland"),
        StringOption("SYR", "Syrian Arab Republic"),
        StringOption("TJ", "Tajikistan"),
        StringOption("EAT", "Tanganyika"),
        StringOption("T", "Thailand"),
        StringOption("MK", "The F.Y.R. of Macedonia"),
        StringOption("TG", "Togo"),
        StringOption("TT", "Trinidad and Tobago"),
        StringOption("TN", "Tunisia"),
        StringOption("TR", "Turkey"),
        StringOption("TM", "Turkmenistan"),
        StringOption("EAU", "Uganda"),
        StringOption("UA", "Ukraine"),
        StringOption("UAEd", "United Arab Emirates"),
        StringOption("GB", "United Kingdom:"),
        StringOption("TZA", "United Republic of Tanzania:"),
        StringOption("USA", "United States of America"),
        StringOption("ROU", "Uruguay"),
        StringOption("UZ", "Uzbekistan"),
        StringOption("YV", "Venezuela"),
        StringOption("VN", "Viet Nam"),
        StringOption("BVI", "Virgin Islands"),
        StringOption("YAR", "Yemen"),
        StringOption("RNR", "Zambia"),
        StringOption("EAZ", "Zanzibar"),
        StringOption("ZW", "Zimbabwe")
    )
}