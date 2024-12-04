package com.android.identity.asn1

import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.LocalTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atTime
import kotlinx.datetime.format
import kotlinx.datetime.format.byUnicodePattern
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.bytestring.ByteStringBuilder
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

class ASN1Time(
    val value: Instant,
    tag: Int = ASN1TimeTag.GENERALIZED_TIME.tag
): ASN1PrimitiveValue(tag) {

    override fun encode(builder: ByteStringBuilder) {
        val ldt = value.toLocalDateTime(TimeZone.UTC)
        val str = when (tag) {
            ASN1TimeTag.UTC_TIME.tag -> {
                // Looks like 'yy' makes LocalDateTime.format() yield '+1950' for years before 2000
                val yearTwoDigits = ldt.year % 100
                val yearTwoDigitsWithPadding = if (yearTwoDigits < 10) {
                    "0" + yearTwoDigits.toString()
                } else {
                    yearTwoDigits.toString()
                }
                val dateTimeFormat = LocalDateTime.Format {
                    byUnicodePattern("MMddHHmmss'Z'")
                }
                yearTwoDigitsWithPadding + ldt.format(dateTimeFormat)
            }

            ASN1TimeTag.GENERALIZED_TIME.tag -> {
                if (ldt.nanosecond > 0) {
                    // From X.690 clause 11.7.3: The fractional-seconds elements, if present,
                    // shall omit all trailing zeros; if the elements correspond to 0,
                    // they shall be wholly omitted, and the decimal point element also shall
                    // be omitted.
                    //
                    val nanoAsStr =
                        (ldt.nanosecond.nanoseconds + 1.seconds).inWholeNanoseconds.toString()
                        .trim('0').substring(1)

                    ldt.format(
                        LocalDateTime.Format {
                            byUnicodePattern("yyyyMMddHHmmss")
                        }
                    ) + "." + nanoAsStr + "Z"
                } else {
                    ldt.format(
                        LocalDateTime.Format {
                            byUnicodePattern("yyyyMMddHHmmss'Z'")
                        }
                    )
                }
            }

            else -> throw IllegalStateException()
        }
        val encoded = str.encodeToByteArray()
        ASN1.appendUniversalTagEncodingLength(builder, tag, enc, encoded.size)
        builder.append(encoded)
    }

    override fun equals(other: Any?): Boolean =
        other is ASN1Time && other.tag == tag && other.value == value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String {
        return "ASN1Time(${tag}, $value)"
    }

    companion object {
        fun parse(content: ByteArray, tag: Int): ASN1Time {
            val str = content.decodeToString()
            val parsedTime = when (tag) {
                ASN1TimeTag.UTC_TIME.tag -> {
                    if (str.length != 13 || str[12] != 'Z') {
                        throw IllegalArgumentException("UTCTime string is malformed")
                    }
                    val yearTwoDigits = str.slice(IntRange(0, 1)).toInt()
                    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
                    val century = if (yearTwoDigits < 50) 2000 else 1900
                    val year = yearTwoDigits + century
                    val month = str.slice(IntRange(2, 3)).toInt()
                    val day = str.slice(IntRange(4, 5)).toInt()
                    val hour = str.slice(IntRange(6, 7)).toInt()
                    val minute = str.slice(IntRange(8, 9)).toInt()
                    val second = str.slice(IntRange(10, 11)).toInt()
                    val ld = LocalDate(year, month, day)
                    val ut = LocalTime(hour, minute, second)
                    ld.atTime(ut).toInstant(TimeZone.UTC)
                }

                ASN1TimeTag.GENERALIZED_TIME.tag -> {
                    val year = str.slice(IntRange(0, 3)).toInt()
                    val month = str.slice(IntRange(4, 5)).toInt()
                    val day = str.slice(IntRange(6, 7)).toInt()
                    val hour = str.slice(IntRange(8, 9)).toInt()
                    val minute = str.slice(IntRange(10, 11)).toInt()
                    val second = str.slice(IntRange(12, 13)).toInt()
                    val nanoSeconds = if (str[14] == 'Z') {
                        if (str.length != 15) {
                            throw IllegalArgumentException("GeneralizedTime string is malformed")
                        }
                        0
                    } else if (str[14] == '.'){
                        if (str[str.length - 1] != 'Z') {
                            throw IllegalArgumentException("GeneralizedTime string is malformed")
                        }
                        val fractionalStr = str.slice(IntRange(15, str.length - 2))
                        LocalTime.parse("00:00:00.$fractionalStr").nanosecond
                    } else {
                        throw IllegalArgumentException("GeneralizedTime string is malformed")
                    }
                    val ld = LocalDate(year, month, day)
                    val ut = LocalTime(hour, minute, second, nanoSeconds)
                    ld.atTime(ut).toInstant(TimeZone.UTC)
                }

                else -> throw IllegalArgumentException("Unsupported tag number")
            }
            return ASN1Time(parsedTime, tag)
        }
    }
}
