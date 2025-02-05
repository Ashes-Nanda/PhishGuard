import nodemailer from 'nodemailer';
import { EmailNotification } from '../types';
import { readFileSync } from 'fs';
import { join } from 'path';
import Handlebars from 'handlebars';

// Create reusable transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Cache for email templates
const templateCache: { [key: string]: HandlebarsTemplateDelegate } = {};

const getTemplate = (templateName: string): HandlebarsTemplateDelegate => {
  if (templateCache[templateName]) {
    return templateCache[templateName];
  }

  const templatePath = join(__dirname, '../templates', `${templateName}.hbs`);
  const templateContent = readFileSync(templatePath, 'utf-8');
  const template = Handlebars.compile(templateContent);
  templateCache[templateName] = template;
  return template;
};

export const sendEmailNotification = async (notification: EmailNotification): Promise<void> => {
  try {
    // Get and compile template
    const template = getTemplate(notification.template);
    const html = template(notification.data);

    // Send email
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: notification.to,
      subject: notification.subject,
      html
    });
  } catch (error) {
    console.error('Error sending email notification:', error);
    throw new Error('Failed to send email notification');
  }
}; 