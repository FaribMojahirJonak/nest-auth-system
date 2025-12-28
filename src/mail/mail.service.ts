import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(private config: ConfigService) {
    const nodeEnv = this.config.get('NODE_ENV');
    const isDev = !nodeEnv || nodeEnv === 'development';

    if (!isDev) {
      this.transporter = nodemailer.createTransport({
        host: this.config.get('MAIL_HOST'),
        port: this.config.get('MAIL_PORT'),
        secure: this.config.get('MAIL_PORT') === 465,
        auth: {
          user: this.config.get('MAIL_USER'),
          pass: this.config.get('MAIL_PASS'),
        },
      });
    }
  }

  async sendPasswordReset(email: string, resetLink: string) {
    const nodeEnv = this.config.get('NODE_ENV');
    const isDev = !nodeEnv || nodeEnv === 'development';

    if (isDev) {
      this.logger.log(
        '\n========== PASSWORD RESET EMAIL ==========\n' +
        `To: ${email}\n` +
        'Subject: Reset your password\n' +
        `Reset Link: ${resetLink}\n` +
        '=========================================\n',
      );
      return;
    }

    try {
      await this.transporter.sendMail({
        from: `"Auth System" <${this.config.get('MAIL_USER')}>`,
        to: email,
        subject: 'Reset your password',
        html: `
          <p>You requested a password reset.</p>
          <p>Click the link below to reset your password:</p>
          <a href="${resetLink}">${resetLink}</a>
          <p>This link expires in 15 minutes.</p>
          <p>If you didn't request this, ignore this email.</p>
        `,
      });
      this.logger.log(`Password reset email sent to: ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send password reset email: ${error.message}`);
      throw error;
    }
  }
}
