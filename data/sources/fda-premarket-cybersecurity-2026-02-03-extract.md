# FDA guidance verbatim extract (pdftotext -layout of the source PDF)

Source: https://www.fda.gov/media/119933/download
Title: Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions. Issued February 3, 2026 (supersedes June 27, 2025). Docket FDA-2021-D-1158, GUI00001825. US Government work (public domain). Text below is pdftotext output, unedited; page headers/footers included as extracted.

## Section V.A.2 through V.A.5 (source text lines 811-1069)
```
                 2.      Cybersecurity Risk Assessment
As a part of security risk management, security risks and controls should be assessed for residual
risks as part of a cybersecurity risk assessment. Effective security risk assessments address the
fact that cybersecurity-related failures can occur either intentionally or unintentionally.
Accordingly, cybersecurity risks are difficult to predict, meaning that it is not possible to assess

34
  The MDIC/MITRE Playbook for Threat Modeling Medical Devices is an educational resource that discusses the
threat modeling process, different threat modeling techniques, and provides fictional medical device examples.


                                                                                                        13
                             Contains Nonbinding Recommendations


and quantify the likelihood of an incident occurring based on historical data or modeling (also
known as a “probabilistic manner”). This non-probabilistic approach is not the fundamental
approach performed in safety risk management under ISO 14971 and further underscores why
safety and security risk management are distinct but connected processes. Instead, security risk
assessment processes focus on exploitability, or the ability to exploit vulnerabilities present
within a device and/or system. FDA recommends that manufacturers assess identified risks
according to the level of risk posed from the device and the system in which it operates.
Additional discussion on exploitability assessments for the security risk assessment can be found
in FDA’s Postmarket Cybersecurity Guidance.

The premarket assessment of exploitability of a cybersecurity risk may be different from the
exploitability assessment of a vulnerability discovered postmarket. In these instances, a
premarket exploitability assessment could either assume a worst-case assessment and implement
appropriate controls, or provide a justification for a reasonable exploitability assessment of the
risk throughout the TPLC and how the risk is controlled.

Acceptance criteria for cybersecurity risks should carefully consider the TPLC of the medical
device system, as it might be more difficult to mitigate cybersecurity issues once the device is
marketed. As discussed above in Sections IV.B and V.A, known vulnerabilities should be
assessed as reasonably foreseeable risks. The cybersecurity risk assessment for vulnerabilities
identified during cybersecurity testing should also consider the TPLC of the device as the
exploitability of the vulnerability is likely to increase over the device lifecycle. If a penetration
tester, for example, was able to exploit a vulnerability, the ability of a threat actor to exploit that
vulnerability is likely to increase over the device lifecycle. Furthermore, vulnerabilities identified
in CISA’s Known Exploited Vulnerabilities Catalog should be designed out of the device, as
they are already being exploited and expose the medical device system and users to the risk.

FDA recommends that the cybersecurity risk assessment provided in premarket submissions
capture the risks and controls identified from the threat model. The methods used for scoring the
risk pre- and post-mitigation and the associated acceptance criteria as well as the method for
transferring security risks into the safety risk assessment process should also be provided as part
of the premarket submission.

               3.      Interoperability Considerations
Interoperability is an important consideration when assessing the cybersecurity of the end-to-end
medical device system. As identified in FDA’s guidance “Design Considerations and Pre-market
Submission Recommendations for Interoperable Medical Devices,” hereafter referred to as the
“Interoperability Guidance,” interoperable medical devices have the ability to exchange and use
information through an electronic interface with another medical or nonmedical product, system,
or device.

As part of a medical device system, a device may have cybersecurity considerations from
interoperable functionality, including but not limited to interfaces with:

   ·   Other medical devices and accessories;



                                                                                                14
                                   Contains Nonbinding Recommendations


       ·   “Other functions” as identified in FDA’s guidance “Multiple Function Device Products:
           Policy and Considerations;”
       ·   Healthcare infrastructure (e.g., network, Electronic Medical Records, medical imaging
           systems); and
       ·   General-purpose computing platforms.

While cybersecurity controls may increase the complexity of interfaces to allow for
interoperability, when properly implemented, the cybersecurity controls can help ensure that
these capabilities remain safe and effective. Cybersecurity controls should be used as a means to
allow for the safe and effective exchange and use of information. Additionally, cybersecurity
controls should not be intended to prohibit a user from accessing their device data.

When common technology and communication protocols are used to enable interoperability
(e.g., Bluetooth, Bluetooth Low Energy, network protocols), device manufacturers should assess
whether added security controls beneath such communication are needed to ensure the safety and
effectiveness of the device (e.g., added security controls beneath Bluetooth Low Energy to
protect against risks if vulnerabilities in the Bluetooth Low Energy protocol or supporting
technology are discovered).

In addition to the recommendations in the Interoperability Guidance, manufacturers should
consider the appropriate cybersecurity risks and controls associated with the interoperability
capabilities and document these considerations as recommended throughout this guidance.

                    4.       Third-Party Software Components
As discussed in FDA’s guidance “Off-The-Shelf (OTS) Software Use in Medical Devices,”
medical devices commonly include third-party software components,35 including off-the-shelf
and open source software. When these components are incorporated, security risks of the
software components should become factors of the overall medical device system risk
management processes and documentation.

As part of demonstrating compliance with design and development under Subclause 7.3 of ISO
13485, and to support supply chain risk management processes, all software, including those
developed by the device manufacturer (“proprietary software”) or obtained from third parties,
should be assessed for cybersecurity risk. Device manufacturers should document all software
components of a device and address or otherwise mitigate risks associated with these software
components.

In addition, under Subclause 7.4 of ISO 13485, a manufacturer must put in place processes and
controls to ensure that its suppliers conform to the manufacturer’s requirements. Such
information is documented in the Design and Development Files, required by Subclause 7.3.10,
and Medical Device File, required by Subclause 4.2.3. This documentation demonstrates the
device’s overall compliance with the QMSR, as well as that the third-party components meet
specifications established for the device. Security risk assessments that include analyses and
considerations of cybersecurity risks that may exist in or be introduced by third-party software

35
     The use of “component” in this guidance is consistent with the definition in 21 CFR 820.3.


                                                                                                  15
                                 Contains Nonbinding Recommendations


and the software supply chain may help demonstrate that manufacturers have adequately ensured
such compliance and documented such history.

Software is updated over time to provide additional features, address security concerns, and
otherwise be maintained. These changes may introduce new considerations or risks that must be
accounted for as part of risk management. As a result, device manufacturers should establish and
maintain custodial control of device source code (the original “copy” of the software) throughout
the lifecycle of a device as part of configuration management.36 This may be accomplished
through different methods, such as source code escrow or source code backups, among others.37

Manufacturers may not have control of source code due to licensing restrictions, terms of
supplier agreements, or other challenges. While source code is not required to be provided in
premarket submissions, manufacturers should include plans for how third-party software
components could be updated or replaced if support ends or other software issues arise in
premarket submissions. The device manufacturer should also provide users with whatever
information they may need in the device labeling to allow them to manage risks associated with
the software components, including known vulnerabilities, configuration specifications, and
other relevant security and risk management considerations.

One tool to help manage supply chain risk as well as clearly identify and track the software
incorporated into a device is an SBOM, as described below.

                      (a)    Software Bill of Materials (SBOM)
An SBOM can aid in the management of cybersecurity risks that exist throughout the software
stack. A robust SBOM includes both the device manufacturer-developed components and third-
party components, including purchased/licensed software and open-source software, and the
upstream software dependencies that are required/depended upon by proprietary,
purchased/licensed, and open-source software.

An SBOM helps facilitate risk management processes by providing a mechanism to identify
devices and the systems in which they operate that might be affected by vulnerabilities in the
software components, both during development when software is being chosen as a component
and after it has been placed into the market throughout all other phases of a product’s life.38

Because vulnerability management is a critical part of a device’s security risk management
processes, an SBOM or an equivalent capability should be maintained as part of the device’s
configuration management, be regularly updated to reflect any changes to the software in
marketed devices, and should support documentation, such as the types detailed in Subclause

36
   While some suppliers may not grant access to source code, manufacturers may consider adding to their purchasing
controls acquisition of the source code should the purchased software reach end of support or end of life from the
supplier earlier than the intended end of support or end of life of the medical device.
37
   Source code escrow involves depositing a copy of a relevant piece of software’s source code (and related technical
components and documentation) with an independent third party (“escrow agent”). Source code backup involves
storing (and updating as needed) a separate copy of the source code.
38
   For additional information, see the Department of Commerce National Telecommunications and Information
Administration’s multi-stakeholder process for software transparency available on the following website NTIA
Software Component Transparency.


                                                                                                             16
                            Contains Nonbinding Recommendations


7.3.10 (Design and Development Files) and Subclause 4.2.3 (Medical Device File) of ISO
13485.

To assist FDA’s assessment of the device risks and associated impacts on safety and
effectiveness related to cybersecurity, FDA recommends that premarket submissions include
SBOM documentation as outlined below. For cyber devices, an SBOM is required (see section
524B(b)(3) of the FD&C Act and Section VII.C.3 of this guidance). SBOMs can also be an
important tool for transparency with users of potential risks as part of labeling as addressed later
in Section VI.

                       (b)    Documentation Supporting Software Bill of Materials
FDA’s guidance document “Off-The-Shelf (OTS) Software Use in Medical Devices” describes
information that should be provided in premarket submissions for software components for
which a manufacturer cannot claim complete software lifecycle control. In addition to the
information recommended in that guidance, manufacturers should provide machine-readable
SBOMs consistent with the minimum elements (also referred to as “baseline attributes”)
identified in the October 2021 National Telecommunications and Information Administration
(NTIA) Multistakeholder Process on Software Component Transparency document “Framing
Software Component Transparency: Establishing a Common Software Bill of Materials
(SBOM).”

In addition to the minimum elements identified by NTIA, for each software component
contained within the SBOM, manufacturers should include in the premarket submission:

   ·   The software level of support provided through monitoring and maintenance from the
       software component manufacturer (e.g., the software is actively maintained, no longer
       maintained, abandoned); and
   ·   The software component’s end-of-support date.

When provided, manufacturers may choose to provide these additional elements as part of the
SBOM, or they may provide it separately, such as in an addendum. Industry-accepted formats of
SBOMs are encouraged.

If a manufacturer is unable to provide the SBOM information to FDA, the manufacturer should
provide a justification for why the information cannot be included in the premarket submission.

As part of the premarket submission, manufacturers should also identify all known
vulnerabilities associated with the device and the software components, including those
identified in CISA’s Known Exploited Vulnerabilities Catalog. For each known vulnerability,
manufacturers should describe how the vulnerabilities were discovered to demonstrate whether
the assessment methods were sufficiently robust. For components with known vulnerabilities,
device manufacturers should provide in premarket submissions:

   ·   A safety and security risk assessment of each known vulnerability (including device and
       system impacts); and



                                                                                              17
                              Contains Nonbinding Recommendations


     ·   Details of applicable safety and security risk controls to address the vulnerability. If risk
         controls include compensating controls, those should be described in an appropriate level
         of detail.

For additional information and discussion regarding proprietary and third-party components, see
Section V.B.2, Security Architecture Views, below.

                5.      Security Assessment of Unresolved Anomalies
FDA’s Premarket Software Guidance recommends that device manufacturers provide a list of
software anomalies that exist in a product at the time of submission. For each anomaly, FDA
recommends that device manufacturers conduct an evaluation of the anomaly’s impact on the
device’s safety and effectiveness, and consult the Premarket Software Guidance to assess the
associated documentation recommended for inclusion in such device’s premarket submission.

Some anomalies discovered during development or testing may have security implications and
may also be considered vulnerabilities. As a part of ensuring a complete security risk assessment
under Subclause 7.1 of ISO 13485, the assessment for impacts to safety and effectiveness may
include an assessment for the potential security impacts of anomalies. The assessment should
also include consideration of any present Common Weakness Enumeration (CWE) categories.39

For example, a clinical user may inadvertently reveal the presence of a previously unknown
software anomaly during normal use, where the impact of the anomaly might occur sporadically
and be assessed to be acceptable from a software risk perspective. Conversely, a threat might
seek out these types of anomalies, and identify means to exploit them in order to manifest the
anomaly’s impact continuously, which could significantly impact the acceptability of the risk
when compared to an anomaly assessment that didn’t include security considerations.

The criteria and rationales for addressing the resulting anomalies with security impacts should be
provided as part of documentation in the premarket submission.

```

## Section VI.B KEV bullet context (lines 1695-1720)
```
FDA recommends that manufacturers submit their cybersecurity management plans as part of
their premarket submissions so that FDA can assess whether the manufacturer has sufficiently
addressed how to maintain the safety and effectiveness of the device after marketing
authorization is achieved. For cyber devices, “a plan to monitor, identify, and address, as
appropriate, in a reasonable time, postmarket cybersecurity vulnerabilities and exploits,
including coordinated vulnerability disclosure and related procedures” is required (see section
524B(b)(1) of the FD&C Act and Section VII.C.1 of this guidance).

Cybersecurity management plans should include the following elements:
   · Personnel responsible;
   · Sources, methods, and frequency for monitoring and identifying vulnerabilities (e.g.,
      researchers, NIST national vulnerability database (NIST NVD), third-party software
      manufacturers);
   · Identify and address vulnerabilities identified in CISA’s Known Exploited Vulnerabilities
      Catalog;
   · Periodic security testing;
   · Timeline to develop and release patches;
   · Update processes;
   · Patching capability (i.e., rate at which update can be delivered to devices);
   · Description of their coordinated vulnerability disclosure process; and
   · Description of how the manufacturer intends to communicate forthcoming remediations,
      patches, and updates to customers.

Additional recommendations on coordinated vulnerability disclosure plans may be found in
FDA’s Postmarket Cybersecurity Guidance.

```

## Context around line 93 (524B(b)(3))
```
           2.     Security Architecture Views ......................................................................................... 22
      C.         Cybersecurity Testing .................................................................................................... 25
VI. Cybersecurity Transparency ................................................................................................. 27
      A.         Labeling Recommendations for Devices with Cybersecurity Risks .............................. 27
      B.         Cybersecurity Management Plans .................................................................................. 30
VII. Cyber Devices ....................................................................................................................... 30
      A.         Who is Required to Comply with Section 524B of the FD&C Act ............................... 31
      B.         Devices Subject to Section 524B of the FD&C Act ...................................................... 31
      C.         Documentation Recommendations to Comply with Section 524B of the FD&C Act ... 32
           1.     Plans and Procedures (Section 524B(b)(1)) .................................................................. 32
                                        Contains Nonbinding Recommendations


        2. Design, Develop, and Maintain Processes and Procedures to Provide a Reasonable
        Assurance of Cybersecurity (Section 524B(b)(2)) ............................................................... 34
        3.    Software Bill of Materials (SBOM) (Section 524B(b)(3)) ........................................... 34
   D.        Modifications ................................................................................................................. 35
        1.    Changes That May Impact Cybersecurity..................................................................... 35
        2.    Changes Unlikely to Impact Cybersecurity .................................................................. 35
   E.        Reasonable Assurance of Cybersecurity of Cyber Devices ........................................... 36
Appendix 1. Security Control Categories and Associated Recommendations ............................. 38
             Authentication ................................................................................................................ 38
             Authorization .................................................................................................................. 40
             Cryptography.................................................................................................................. 41
             Code, Data, and Execution Integrity .............................................................................. 42
             Confidentiality................................................................................................................ 43
             Event Detection and Logging......................................................................................... 43
             Resiliency and Recovery ................................................................................................ 45
             Firmware and Software Updates .................................................................................... 45
Appendix 2. Submission Documentation for Security Architecture Flows .................................. 47
   A.        Diagrams ........................................................................................................................ 47
```

## Context around line 994 (524B(b)(3))
```
   For additional information, see the Department of Commerce National Telecommunications and Information
Administration’s multi-stakeholder process for software transparency available on the following website NTIA
Software Component Transparency.


                                                                                                             16
                            Contains Nonbinding Recommendations


7.3.10 (Design and Development Files) and Subclause 4.2.3 (Medical Device File) of ISO
13485.

To assist FDA’s assessment of the device risks and associated impacts on safety and
effectiveness related to cybersecurity, FDA recommends that premarket submissions include
SBOM documentation as outlined below. For cyber devices, an SBOM is required (see section
524B(b)(3) of the FD&C Act and Section VII.C.3 of this guidance). SBOMs can also be an
important tool for transparency with users of potential risks as part of labeling as addressed later
in Section VI.

                       (b)    Documentation Supporting Software Bill of Materials
FDA’s guidance document “Off-The-Shelf (OTS) Software Use in Medical Devices” describes
information that should be provided in premarket submissions for software components for
which a manufacturer cannot claim complete software lifecycle control. In addition to the
information recommended in that guidance, manufacturers should provide machine-readable
SBOMs consistent with the minimum elements (also referred to as “baseline attributes”)
identified in the October 2021 National Telecommunications and Information Administration
(NTIA) Multistakeholder Process on Software Component Transparency document “Framing
Software Component Transparency: Establishing a Common Software Bill of Materials
(SBOM).”

In addition to the minimum elements identified by NTIA, for each software component
```

## Context around line 1948 (524B(b)(3))
```
                             Cybersecurity (Section 524B(b)(2))
Manufacturers of cyber devices must “design, develop, and maintain processes and procedures to
provide a reasonable assurance that the device and related systems are cybersecure . . .” (section
524B(b)(2) of the FD&C Act). FDA considers related systems to include, among other things,
manufacturer-controlled elements, such as other devices, software that performs “other
functions” as described in FDA’s Guidance “Multiple Function Device Products: Policy and
Considerations,” software/firmware update servers, and connections to healthcare facility
networks. In the design, development and maintenance of a cyber device, manufacturers should
consider the cybersecurity risks of related systems to the cyber device and implement appropriate
security controls to mitigate those risks. The documentation recommendations identified in this
guidance and summarized in Appendix 4 should be considered and used to demonstrate
reasonable assurance that the device and related systems are cybersecure as required by section
524B(b)(2).


                           3. Software Bill of Materials (SBOM) (Section 524B(b)(3))
Section 524B(b)(3) of the FD&C Act requires manufacturers of cyber devices to provide an
SBOM, including commercial, open-source, and off-the-shelf software components. To assist
with complying with this requirement, we recommend that a cyber device provide SBOMs that
contain the information recommended in Section V.A.4.b.

67
   See section 524B(b)(1) of the FD&C Act.
68
   See section 524B(b)(2) of the FD&C Act.
69
   See section 524B(b)(1) of the FD&C Act.
70
   See section 524B(b)(2) of the FD&C Act.


```
