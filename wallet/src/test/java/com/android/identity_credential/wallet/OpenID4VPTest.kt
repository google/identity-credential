package com.android.identity_credential.wallet

import com.android.identity.document.DocumentRequest
import com.android.identity_credential.wallet.presentation.DescriptorMap
import com.android.identity_credential.wallet.presentation.createPresentationSubmission
import com.android.identity_credential.wallet.presentation.formatAsDocumentRequest
import com.android.identity_credential.wallet.presentation.getAuthRequestFromJwt
import com.android.identity_credential.wallet.presentation.parsePathItem
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.Json.Default.parseToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert
import org.junit.Test

class OpenID4VPTest {

    // real-life example from https://verifier.eudiw.dev/home
    private val eudiAgeOver18RequestObject = "eyJ4NWMiOlsiTUlJREtqQ0NBckNnQXdJQkFnSVVmeTl1NlNMdGdOdWY5UFhZYmgvUURxdVh6NTB3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFVRUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1ESXlOakF5TXpZek0xb1hEVEkyTURJeU5UQXlNell6TWxvd2FURWRNQnNHQTFVRUF3d1VSVlZFU1NCU1pXMXZkR1VnVm1WeWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1WbVpYSmxibU5sSUVsdGNHeGxiV1Z1ZEdGMGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk1iV0JBQzFHaitHRE8veUNTYmdiRndwaXZQWVdMekV2SUxOdGRDdjdUeDFFc3hQQ3hCcDNEWkI0RklyNEJsbVZZdEdhVWJvVklpaFJCaVFEbzNNcFdpamdnRkJNSUlCUFRBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkxOc3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DVUdBMVVkRVFRZU1CeUNHblpsY21sbWFXVnlMV0poWTJ0bGJtUXVaWFZrYVhjdVpHVjJNQklHQTFVZEpRUUxNQWtHQnlpQmpGMEZBUVl3UXdZRFZSMGZCRHd3T2pBNG9EYWdOSVl5YUhSMGNITTZMeTl3Y21Wd2NtOWtMbkJyYVM1bGRXUnBkeTVrWlhZdlkzSnNMM0JwWkY5RFFWOVZWRjh3TVM1amNtd3dIUVlEVlIwT0JCWUVGRmdtQWd1QlN2U25tNjhaem81SVN0SXYyZk0yTUE0R0ExVWREd0VCL3dRRUF3SUhnREJkQmdOVkhSSUVWakJVaGxKb2RIUndjem92TDJkcGRHaDFZaTVqYjIwdlpYVXRaR2xuYVhSaGJDMXBaR1Z1ZEdsMGVTMTNZV3hzWlhRdllYSmphR2wwWldOMGRYSmxMV0Z1WkMxeVpXWmxjbVZ1WTJVdFpuSmhiV1YzYjNKck1Bb0dDQ3FHU000OUJBTUNBMmdBTUdVQ01RREdmZ0xLbmJLaGlPVkYzeFNVMGFlanUvbmVHUVVWdU5ic1F3MExlRER3SVcrckxhdGViUmdvOWhNWERjM3dybFVDTUFJWnlKN2xSUlZleU1yM3dqcWtCRjJsOVliMHdPUXBzblpCQVZVQVB5STV4aFdYMlNBYXpvbTJKanNOL2FLQWtRPT0iLCJNSUlESFRDQ0FxT2dBd0lCQWdJVVZxamd0SnFmNGhVWUprcWRZemkrMHh3aHdGWXdDZ1lJS29aSXpqMEVBd013WERFZU1Cd0dBMVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1CNFhEVEl6TURrd01URTRNelF4TjFvWERUTXlNVEV5TnpFNE16UXhObG93WERFZU1Cd0dBMVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFRmc1U2hmc3hwNVIvVUZJRUtTM0wyN2R3bkZobmpTZ1VoMmJ0S09RRW5mYjNkb3llcU1BdkJ0VU1sQ2xoc0YzdWVmS2luQ3cwOE5CMzFyd0MrZHRqNlgvTEUzbjJDOWpST0lVTjhQcm5sTFM1UXM0UnM0WlU1T0lnenRvYU84RzlvNElCSkRDQ0FTQXdFZ1lEVlIwVEFRSC9CQWd3QmdFQi93SUJBREFmQmdOVkhTTUVHREFXZ0JTemJMaVJGeHpYcEJwbU1ZZEM0WXZBUU15Vkd6QVdCZ05WSFNVQkFmOEVEREFLQmdncmdRSUNBQUFCQnpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRpOWpjbXd2Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVczJ5NGtSY2MxNlFhWmpHSFF1R0x3RURNbFJzd0RnWURWUjBQQVFIL0JBUURBZ0VHTUYwR0ExVWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFrYVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0WVc1a0xYSmxabVZ5Wlc1alpTMW1jbUZ0WlhkdmNtc3dDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXdhWFVBM2orK3hsL3RkRDc2dFhFV0Npa2ZNMUNhUno0dnpCQzdOUzB3Q2RJdEtpejZIWmVWOEVQdE5DbnNmS3BOQWpFQXFyZGVLRG5yNUt3ZjhCQTd0QVRlaHhObE9WNEhuYzEwWE8xWFVMdGlnQ3diNDlScGtxbFMySHVsK0RwcU9iVXMiXSwidHlwIjoib2F1dGgtYXV0aHotcmVxK2p3dCIsImFsZyI6IkVTMjU2In0.eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9kaXJlY3RfcG9zdCIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6IjliNGYwNGEzLTgzMjgtNGE4Ny1iMGYxLTIzNTBmNjJkNDczNiIsImNsaWVudF9pZCI6InZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2IiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsImF1ZCI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIiLCJzY29wZSI6IiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzJmNTQxNjMtNzE2Ni00OGYxLTkzZDgtZmYyMTdiZGIwNjUzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwibmFtZSI6IkVVREkgUElEIiwicHVycG9zZSI6IldlIG5lZWQgdG8gdmVyaWZ5IHlvdXIgaWRlbnRpdHkiLCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIiwiRVNCMjU2IiwiRVNCMzIwIiwiRVNCMzg0IiwiRVNCNTEyIl19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydhZ2Vfb3Zlcl8xOCddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfV19fV19LCJzdGF0ZSI6IjQ0elo3Rm1yTTRuU3VvNWNKb1FYMkd4MXBLaW9Bd1ZiTl9nT2FTT1IxTi1HR2kySmZDa3k2NDFSMVVzU0pUNmJLMkFMTzR6VVE3U09WeWMwbWR5NWt3IiwiaWF0IjoxNzE2MjIxMDExLCJjbGllbnRfbWV0YWRhdGEiOnsiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkExMjhDQkMtSFMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiUlNBLU9BRVAtMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkExMjhDQkMtSFMyNTYiLCJqd2tzX3VyaSI6Imh0dHBzOi8vdmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYvd2FsbGV0L2phcm0vNDR6WjdGbXJNNG5TdW81Y0pvUVgyR3gxcEtpb0F3VmJOX2dPYVNPUjFOLUdHaTJKZkNreTY0MVIxVXNTSlQ2YksyQUxPNHpVUTdTT1Z5YzBtZHk1a3cvandrcy5qc29uIiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifX0.xLzRWy-mPHPC3oaczv71R1eaz_7kumUVC1CIx3wpt2v6HjZa6vQIhyISGGNgdqANBvAs-xiSXzFYp-zcVOQCDQ"
    // the request object in ISO 18013-7 Annex B
    private val annexBRequestObject = "eyJ4NWMiOlsiTUlJQ1B6Q0NBZVdnQXdJQkFnSVVEbUJYeDcrMTlLaHdqbHREYkJXNEJFMENSUkV3Q2dZSUtvWkl6ajBFQXdJd2FURUxNQWtHIEExVUVCaE1DVlZReER6QU5CZ05WQkFnTUJsVjBiM0JwWVRFTk1Bc0dBMVVFQnd3RVEybDBlVEVTTUJBR0ExVUVDZ3dKUVVOTlIgU0JEYjNKd01SQXdEZ1lEVlFRTERBZEpWQ0JFWlhCME1SUXdFZ1lEVlFRRERBdGxlR0Z0Y0d4bExtTnZiVEFlRncweU16RXdNRCBNeE5EUTVNemhhRncweU5EQTVNak14TkRRNU16aGFNR2t4Q3pBSkJnTlZCQVlUQWxWVU1ROHdEUVlEVlFRSURBWlZkRzl3YVdFIHhEVEFMQmdOVkJBY01CRU5wZEhreEVqQVFCZ05WQkFvTUNVRkRUVVVnUTI5eWNERVFNQTRHQTFVRUN3d0hTVlFnUkdWd2RERVUgTUJJR0ExVUVBd3dMWlhoaGJYQnNaUzVqYjIwd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSZkxoK2NXWHE1ZiBXUmY5Q3dvOFZSa3A5QUFPT0xhUDNVQ2kzWVkxVkRISEV4N2xBbjlNQ1hvL3ZuaXFMODhWRkVpMVB0VDlPRGFJTlZJWFpGRmpPIHJZbzJzd2FUQWRCZ05WSFE0RUZnUVV4djZIdFJRazlxN0FTUUNVcU9xRXVuNVM4UVF3SHdZRFZSMGpCQmd3Rm9BVXh2Nkh0UlEgazlxN0FTUUNVcU9xRXVuNVM4UVF3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFXQmdOVkhSRUVEekFOZ2d0bGVHRnRjR3hsTG1OdiBiVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUJ0NS9tYWl4SnlhV05LRzhXOWRBZVBodmhoNU9IanN3SmFFamN5WWlxb29nSWhBIE53VEdUZGcxMlJFelFNZlFTWFRTVnROcDFqakpNUHNpcHFSN2tJSzFKZFQiXSwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJtREwtc2FtcGxlLXJlcSIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6Im9yZy5pc28uMTgwMTMuNS4xLm1ETCAiLCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIiwiRVNCMjU2IiwiRVNCMzIwIiwiRVNCMzg0IiwiRVNCNTEyIl19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2JpcnRoX2RhdGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2RvY3VtZW50X251bWJlciddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZHJpdmluZ19wcml2aWxlZ2VzJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydleHBpcnlfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZmFtaWx5X25hbWUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2dpdmVuX25hbWUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2lzc3VlX2RhdGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2lzc3VpbmdfYXV0aG9yaXR5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydpc3N1aW5nX2NvdW50cnknXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ3BvcnRyYWl0J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWyd1bl9kaXN0aW5ndWlzaGluZ19zaWduJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XSwibGltaXRfZGlzY2xvc3VyZSI6InJlcXVpcmVkIn19XX0sImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwidXNlIjoiZW5jIiwiY3J2IjoiUC0yNTYiLCJ4IjoieFZMdFphUFBLLXh2cnVoMWZFQ2xOVlRSNlJDWkJzUWFpMi1Ecm55S2t4ZyIsInkiOiItNS1RdEZxSnFHd09qRUwzVXQ4OW5yRTBNZWFVcDVSb3prc0tIcEJpeXcwIiwiYWxnIjoiRUNESC1FUyIsImtpZCI6IlA4cDB2aXJSbGg2ZkFraDUtWVNlSHQ0RUl2LWhGR25lWWsxNGQ4REY1MXcifV19LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInZwX2Zvcm1hdHMiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIiwiRVNCMjU2IiwiRVNCMzIwIiwiRVNCMzg0IiwiRVNCNTEyIl19fX0sInN0YXRlIjoiMzRhc2ZkMzRfMzQkMzQiLCJub25jZSI6IlNhZmRhZXKnJDQ1XzMzNDIiLCJjbGllbnRfaWQiOiJleGFtcGxlLmNvbSAiLCJjbGllbnRfaWRfc2NoZW1lIjoieDUwOV9zYW5fZG5zIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vMTIzNDUvcmVzcG9uc2UifQ.DIEllOaSydngto5RYP-W5eWifqcqylKuRXYoZwtSo8ekWPkTE1_IfabbpkYCS9Y42HuAbuKiVQCN2OKAyabEwA"

    @Test
    fun testParsePath() {
        Assert.assertEquals(Pair("namespace", "dataElem"), parsePathItem("\"\$['namespace']['dataElem']\""))
    }

    @Test
    fun eudiwJwtToPresentationSubmission() {
        val authRequest = getAuthRequestFromJwt(SignedJWT.parse(eudiAgeOver18RequestObject), "verifier-backend.eudiw.dev")
        Assert.assertEquals(parseToJsonElement(
                "{\"input_descriptors\":" +
                    "[{\"id\":\"eu.europa.ec.eudiw.pid.1\"," +
                    "\"name\":\"EUDI PID\"," +
                    "\"purpose\":\"We need to verify your identity\"," +
                    "\"format\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"ESB256\",\"ESB320\",\"ESB384\",\"ESB512\"]}}," +
                    "\"constraints\":{\"fields\":[{\"path\":[\"\$['eu.europa.ec.eudiw.pid.1']['age_over_18']\"],\"intent_to_retain\":false}]}}]," +
                "\"id\":\"32f54163-7166-48f1-93d8-ff217bdb0653\"}"),
            authRequest.presentationDefinition
        )
        Assert.assertEquals("verifier-backend.eudiw.dev", authRequest.clientId)
        Assert.assertEquals("9b4f04a3-8328-4a87-b0f1-2350f62d4736", authRequest.nonce)
        Assert.assertEquals("https://verifier-backend.eudiw.dev/wallet/direct_post",
            authRequest.responseUri)
        Assert.assertEquals("44zZ7FmrM4nSuo5cJoQX2Gx1pKioAwVbN_gOaSOR1N-GGi2JfCky641R1UsSJT6bK2ALO4zUQ7SOVyc0mdy5kw",
            authRequest.state)
        Assert.assertEquals(parseToJsonElement(
                "{\"authorization_encrypted_response_alg\":\"ECDH-ES\"," +
                "\"authorization_encrypted_response_enc\":\"A128CBC-HS256\"," +
                "\"id_token_encrypted_response_alg\":\"RSA-OAEP-256\"," +
                "\"id_token_encrypted_response_enc\":\"A128CBC-HS256\"," +
                "\"jwks_uri\":\"https://verifier-backend.eudiw.dev/wallet/jarm/44zZ7FmrM4nSuo5cJoQX2Gx1pKioAwVbN_gOaSOR1N-GGi2JfCky641R1UsSJT6bK2ALO4zUQ7SOVyc0mdy5kw/jwks.json\"," +
                "\"subject_syntax_types_supported\":[\"urn:ietf:params:oauth:jwk-thumbprint\"]," +
                "\"id_token_signed_response_alg\":\"RS256\"}"),
            authRequest.clientMetadata!!)

        val presentationSubmission = createPresentationSubmission(authRequest)
        Assert.assertEquals("32f54163-7166-48f1-93d8-ff217bdb0653",
            presentationSubmission.definitionId)
        val descriptorMaps = presentationSubmission.descriptorMaps
        for (descriptorMap: DescriptorMap in descriptorMaps) {
            Assert.assertEquals("eu.europa.ec.eudiw.pid.1", descriptorMap.id)
            Assert.assertEquals("mso_mdoc", descriptorMap.format)
            Assert.assertEquals("$", descriptorMap.path)
        }

        val docRequest = formatAsDocumentRequest(authRequest.presentationDefinition["input_descriptors"]!!.jsonArray[0].jsonObject)
        val expectedRequestedElems = listOf(
            DocumentRequest.DataElement("eu.europa.ec.eudiw.pid.1", "age_over_18", false))
        Assert.assertEquals(expectedRequestedElems, docRequest.requestedDataElements)
    }

    @Test
    fun annexBJwtToPresentationSubmission() {
        val authRequest = getAuthRequestFromJwt(SignedJWT.parse(annexBRequestObject), "example.com ")
        Assert.assertEquals(parseToJsonElement(
            "{\"input_descriptors\":" +
                    "[{\"id\":\"org.iso.18013.5.1.mDL \"," +
                    "\"format\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"ESB256\",\"ESB320\",\"ESB384\",\"ESB512\"]}}," +
                    "\"constraints\":{\"fields\":" +
                        "[{\"path\":[\"\$['org.iso.18013.5.1']['birth_date']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['document_number']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['driving_privileges']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['expiry_date']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['family_name']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['given_name']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['issue_date']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['issuing_authority']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['issuing_country']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['portrait']\"],\"intent_to_retain\":false}," +
                        "{\"path\":[\"\$['org.iso.18013.5.1']['un_distinguishing_sign']\"],\"intent_to_retain\":false}]," +
                    "\"limit_disclosure\":\"required\"}}]," +
                    "\"id\":\"mDL-sample-req\"}\n"),
            authRequest.presentationDefinition
        )
        Assert.assertEquals("example.com ", authRequest.clientId)
        Assert.assertEquals("Safdaer�\$45_3342", authRequest.nonce)
        Assert.assertEquals("https://example.com/12345/response",
            authRequest.responseUri)
        Assert.assertEquals("34asfd34_34\$34", authRequest.state)
        Assert.assertEquals(parseToJsonElement(
            "{\"authorization_encrypted_response_alg\":\"ECDH-ES\"," +
                    "\"authorization_encrypted_response_enc\":\"A256GCM\"," +
                    "\"jwks\":{\"keys\":[{" +
                        "\"kty\":\"EC\"," +
                        "\"use\":\"enc\"," +
                        "\"crv\":\"P-256\"," +
                        "\"x\":\"xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg\"," +
                        "\"y\":\"-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0\"," +
                        "\"alg\":\"ECDH-ES\"," +
                        "\"kid\":\"P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w\"}]}," +
                    "\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"ESB256\",\"ESB320\",\"ESB384\",\"ESB512\"]}}}\n"),
            authRequest.clientMetadata!!)

        val presentationSubmission = createPresentationSubmission(authRequest)
        val descriptorMaps = presentationSubmission.descriptorMaps
        for (descriptorMap: DescriptorMap in descriptorMaps) {
            Assert.assertEquals("org.iso.18013.5.1.mDL ", descriptorMap.id)
            Assert.assertEquals("mso_mdoc", descriptorMap.format)
            Assert.assertEquals("$", descriptorMap.path)
        }

        val docRequest = formatAsDocumentRequest(authRequest.presentationDefinition["input_descriptors"]!!.jsonArray[0].jsonObject)
        val expectedRequestedElems = listOf(
            DocumentRequest.DataElement("org.iso.18013.5.1", "birth_date", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "document_number", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "driving_privileges", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "expiry_date", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "family_name", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "given_name", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "issue_date", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "issuing_authority", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "issuing_country", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "portrait", false),
            DocumentRequest.DataElement("org.iso.18013.5.1", "un_distinguishing_sign", false))
        Assert.assertEquals(expectedRequestedElems, docRequest.requestedDataElements)
    }
}