import fs from 'fs';
import path from 'path';
import markdownpdf from 'markdown-pdf';

/**
 * Generate a PDF report from markdown content
 * @param {string} markdownContent - The markdown content to convert to PDF
 * @param {string} outputPath - The path to save the PDF file
 * @returns {Promise<string>} - The path to the generated PDF file
 */
export async function generatePDFReport(markdownContent, outputPath) {
  try {
    // Add header with creator information
    const headerInfo = `# Security Scan Report

*Created by: Ayash Ahmad*  
*Email: bhatashu666@gmail.com*

---

`;
    
    // Combine header with the original content
    const contentWithHeader = headerInfo + markdownContent;
    
    // Create a temporary markdown file
    const tempMdPath = outputPath.replace('.pdf', '-temp.md');
    fs.writeFileSync(tempMdPath, contentWithHeader);
    
    // Convert markdown to PDF
    return new Promise((resolve, reject) => {
      markdownpdf()
        .from(tempMdPath)
        .to(outputPath, () => {
          // Clean up temporary file
          try {
            fs.unlinkSync(tempMdPath);
          } catch (cleanupError) {
            console.warn('Warning: Could not delete temporary markdown file:', cleanupError);
          }
          
          console.log(`PDF report generated at ${outputPath}`);
          resolve(outputPath);
        });
    });
  } catch (error) {
    console.error('Error generating PDF report:', error);
    throw error;
  }
}