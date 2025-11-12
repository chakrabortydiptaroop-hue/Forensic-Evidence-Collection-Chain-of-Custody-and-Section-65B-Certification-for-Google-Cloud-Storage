"""
Section 65B Certificate Generator Module
Generates legally compliant certificates for digital evidence admissibility in Indian courts
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠   WARNING: reportlab not installed")
    print("   Install: pip install reportlab")


class Section65BCertificate:
    """Generates legal Section 65B(4) certificate for Indian courts"""
    
    def __init__(self, evidence_data: Dict[str, Any], hash_value: str, 
                 collector_name: str = "Forensic Analyst", 
                 organization: str = "",
                 collector_designation: str = "Forensic Examiner"):
        """
        Initialize certificate with evidence details
        
        Args:
            evidence_data: Dictionary containing evidence metadata
            hash_value: SHA-256 hash of the evidence
            collector_name: Name of the person collecting evidence
            organization: Organization name
            collector_designation: Job title of collector
        """
        self.certificate_number = str(uuid.uuid4())
        self.evidence_id = evidence_data.get('evidence_id')
        self.bucket = evidence_data.get('bucket')
        self.project = evidence_data.get('project')
        self.collection_time = evidence_data.get('timestamp')
        self.hash_value = hash_value
        self.collector_name = collector_name
        self.organization = organization or "Not specified"
        self.collector_designation = collector_designation
        self.generated_time = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    def generate_text_certificate(self, output_dir: str = "output") -> str:
        """Generate plain text version of certificate"""
        text = self._generate_certificate_content()
        
        os.makedirs(output_dir, exist_ok=True)
        cert_file = os.path.join(output_dir, f"{self.evidence_id}_section65b_certificate.txt")
        
        with open(cert_file, "w", encoding="utf-8") as f:
            f.write(text)
        
        print(f"✅ Text certificate generated: {cert_file}")
        return cert_file

    def generate_pdf_certificate(self, output_dir: str = "output") -> str:
        """Generate PDF version of certificate"""
        if not REPORTLAB_AVAILABLE:
            print("❌ Cannot generate PDF: reportlab not installed")
            print("   Falling back to text certificate...")
            return self.generate_text_certificate(output_dir)
        
        os.makedirs(output_dir, exist_ok=True)
        cert_file = os.path.join(output_dir, f"{self.evidence_id}_section65b_certificate.pdf")
        
        doc = SimpleDocTemplate(
            cert_file,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        styles = self._get_custom_styles()
        
        # Title
        story.append(Paragraph("SECTION 65B(4) CERTIFICATE", styles['CertTitle']))
        story.append(Paragraph("(Indian Evidence Act, 1872)", styles['CertSubtitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Certificate Details Table
        cert_data = [
            ['Certificate Number:', self.certificate_number],
            ['Evidence ID:', self.evidence_id],
            ['GCP Project:', self.project],
            ['Cloud Storage Bucket:', self.bucket],
            ['Collected By:', self.collector_name],
            ['Designation:', self.collector_designation],
            ['Organization:', self.organization],
            ['Collection Time (UTC):', self.collection_time],
            ['Certificate Generated:', self.generated_time],
        ]
        
        cert_table = Table(cert_data, colWidths=[2.5*inch, 4*inch])
        cert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(cert_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Evidence Hash
        hash_data = [['Evidence Hash (SHA-256):', self.hash_value]]
        hash_table = Table(hash_data, colWidths=[2.5*inch, 4*inch])
        hash_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, 0), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(hash_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Declaration Section
        story.append(Paragraph("DECLARATION", styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        declaration = f"""I, <b>{self.collector_name}</b>, being duly authorized to certify under 
        Section 65B(4) of the Indian Evidence Act, 1872, hereby declare that:"""
        story.append(Paragraph(declaration, styles['CertBodyText']))
        story.append(Spacer(1, 0.1*inch))
        
        # Declaration Points
        declarations = [
            "I am the person who collected/produced the electronic record described above from the Google Cloud Platform storage bucket.",
            
            "The electronic record was produced by a computer system that was, at the time of production, functioning properly and correctly, without any disturbance, interruption, or error.",
            
            "The computer system and data storage have been maintained in a secure manner to prevent unauthorized access, modification, or alteration.",
            
            "The computer system employed proper access controls and audit logging to ensure the integrity and authenticity of the electronic records.",
            
            "The electronic record has not been altered, modified, tampered with, or manipulated in any manner since its production by the computer system.",
            
            "The hash value (SHA-256) provided above serves as a cryptographic fingerprint of the evidence and can be used to verify its integrity.",
            
            "I am competent to testify and have personal knowledge of the facts stated in this certificate.",
            
            "This certificate is being produced to authenticate the electronic record as evidence in legal proceedings as per Section 65B of the Indian Evidence Act, 1872."
        ]
        
        for i, decl in enumerate(declarations, 1):
            story.append(Paragraph(f"<b>{i}.</b> {decl}", styles['DeclarationText']))
            story.append(Spacer(1, 0.08*inch))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Signature Section
        story.append(Paragraph("SIGNATURE AND ATTESTATION", styles['SectionHeader']))
        story.append(Spacer(1, 0.15*inch))
        
        story.append(Paragraph("Signature of Certifying Officer:", styles['CertBodyText']))
        story.append(Spacer(1, 0.4*inch))
        story.append(Paragraph("_" * 60, styles['SignatureLine']))
        story.append(Spacer(1, 0.15*inch))
        
        signature_data = [
            [f"Name: {self.collector_name}", f"Date: {'_' * 25}"],
            [f"Designation: {self.collector_designation}", f"Organization: {self.organization}"],
            [f"Contact Email: {'_' * 35}", f"Contact Phone: {'_' * 25}"]
        ]
        
        sig_table = Table(signature_data, colWidths=[3.25*inch, 3.25*inch])
        sig_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(sig_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Legal Notes
        story.append(Paragraph("LEGAL ADMISSIBILITY NOTES", styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        legal_note = """This certificate complies with Section 65B(4) of the Indian Evidence Act, 1872. 
        The electronic record described herein is admissible in evidence in courts of law in India 
        if accompanied by this certificate signed by the certifying officer."""
        story.append(Paragraph(legal_note, styles['CertBodyText']))
        story.append(Spacer(1, 0.1*inch))
        
        references = """For more information about digital evidence admissibility in Indian courts, refer to:<br/>
        • Indian Evidence Act, 1872 (Section 65A-65C)<br/>
        • The Information Technology Act, 2000<br/>
        • Supreme Court precedents on electronic evidence"""
        story.append(Paragraph(references, styles['CertBodyText']))
        
        # Build PDF
        doc.build(story)
        print(f"✅ PDF certificate generated: {cert_file}")
        return cert_file

    def _generate_certificate_content(self) -> str:
        """Generate the text content of the certificate"""
        return f"""╔══════════════════════════════════════════════════════════════╗
║           SECTION 65B(4) CERTIFICATE                           ║
║          (Indian Evidence Act, 1872)                           ║
╚══════════════════════════════════════════════════════════════╝

Certificate Number:        {self.certificate_number}
Evidence ID:               {self.evidence_id}
GCP Project:               {self.project}
Cloud Storage Bucket:      {self.bucket}
Collected By:              {self.collector_name}
Designation:               {self.collector_designation}
Organization:              {self.organization}
Collection Time (UTC):     {self.collection_time}
Certificate Generated:     {self.generated_time}
Evidence Hash (SHA-256):   {self.hash_value}

{"─" * 70}

DECLARATION:

I, {self.collector_name}, being duly authorized to certify under 
Section 65B(4) of the Indian Evidence Act, 1872, hereby declare that:

1.  I am the person who collected/produced the electronic record 
described above from the Google Cloud Platform storage bucket.

2.  The electronic record was produced by a computer system that was, 
at the time of production, functioning properly and correctly, without 
any disturbance, interruption, or error.

3.  The computer system and data storage have been maintained in a 
secure manner to prevent unauthorized access, modification, or alteration.

4.  The computer system employed proper access controls and audit logging 
to ensure the integrity and authenticity of the electronic records.

5.  The electronic record has not been altered, modified, tampered with, 
or manipulated in any manner since its production by the computer system.

6.  The hash value (SHA-256) provided above serves as a cryptographic 
fingerprint of the evidence and can be used to verify its integrity.

7.  I am competent to testify and have personal knowledge of the facts 
stated in this certificate.

8.  This certificate is being produced to authenticate the electronic 
record as evidence in legal proceedings as per Section 65B of the Indian 
Evidence Act, 1872.

{"─" * 70}

SIGNATURE AND ATTESTATION:

Signature of Certifying Officer:

_______________________________

Name: {self.collector_name}
Date: ______________________

Designation: {self.collector_designation}

Organization: {self.organization}

Contact Email: ________________________

Contact Phone: ________________________

{"─" * 70}

LEGAL ADMISSIBILITY NOTES:

This certificate complies with Section 65B(4) of the Indian Evidence Act, 1872.
The electronic record described herein is admissible in evidence in courts of law 
in India if accompanied by this certificate signed by the certifying officer.

For more information about digital evidence admissibility in Indian courts, 
refer to:
- Indian Evidence Act, 1872 (Section 65A-65C)
- The Information Technology Act, 2000
- Supreme Court precedents on electronic evidence
"""

    def _get_custom_styles(self):
        """Create custom styles for PDF generation"""
        styles = getSampleStyleSheet()
        
        styles.add(ParagraphStyle(
            name='CertTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        styles.add(ParagraphStyle(
            name='CertSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#4a4a4a'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique'
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=12,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=6,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderPadding=0,
            borderColor=colors.black,
            borderRadius=0
        ))
        
        styles.add(ParagraphStyle(
            name='CertBodyText',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
            fontName='Helvetica'
        ))
        
        styles.add(ParagraphStyle(
            name='DeclarationText',
            parent=styles['Normal'],
            fontSize=9,
            alignment=TA_JUSTIFY,
            leftIndent=0,
            fontName='Helvetica'
        ))
        
        styles.add(ParagraphStyle(
            name='SignatureLine',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_LEFT,
            fontName='Helvetica'
        ))
        
        return styles


def create_certificate(evidence_data: Dict[str, Any], 
                      hash_value: str,
                      collector_name: str = "Forensic Analyst",
                      organization: str = "",
                      collector_designation: str = "Forensic Examiner",
                      output_dir: str = "output",
                      format: str = "pdf") -> str:
    """
    Convenience function to create a certificate
    
    Args:
        evidence_data: Dictionary with evidence metadata
        hash_value: SHA-256 hash of evidence
        collector_name: Name of evidence collector
        organization: Organization name
        collector_designation: Job title
        output_dir: Output directory path
        format: 'pdf', 'text', or 'both'
    
    Returns:
        Path to generated certificate file (or PDF if both formats)
    """
    cert = Section65BCertificate(
        evidence_data=evidence_data,
        hash_value=hash_value,
        collector_name=collector_name,
        organization=organization,
        collector_designation=collector_designation
    )
    
    if format.lower() == 'pdf':
        return cert.generate_pdf_certificate(output_dir)
    elif format.lower() == 'text':
        return cert.generate_text_certificate(output_dir)
    elif format.lower() == 'both':
        cert.generate_text_certificate(output_dir)
        return cert.generate_pdf_certificate(output_dir)
    else:
        raise ValueError(f"Invalid format: {format}. Use 'pdf', 'text', or 'both'")