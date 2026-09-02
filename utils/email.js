import nodemailer from "nodemailer";
import dotenv from "dotenv"
dotenv.config();

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

transporter.verify((error, success) => {
    if (error) {
        console.log("SMTP ERROR:", error.message);
    } else {
        console.log("SMTP SERVER READY");
    }
});

export const sendOTPEmail = async (email, otp) => {
    await transporter.sendMail({
        from: `"Secure Auth" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Verify your email address",

        text: `
Hello,

Your Secure Auth verification code is:

${otp}

This code will expire in 5 minutes.

If you did not request this code, you can safely ignore this email.

Regards,
Secure Auth Team
        `,

        html: `
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
                <h2>Verify Your Email</h2>

                <p>Hello,</p>

                <p>
                    Use the following verification code to complete your registration:
                </p>

                <div style="
                    font-size: 30px;
                    font-weight: bold;
                    letter-spacing: 8px;
                    padding: 15px;
                    background: #f3f3f3;
                    text-align: center;
                    margin: 20px 0;
                ">
                    ${otp}
                </div>

                <p>
                    This code will expire in <strong>5 minutes</strong>.
                </p>

                <p>
                    If you did not request this code, you can safely ignore this email.
                </p>

                <hr>

                <small>
                    Secure Auth Team
                </small>
            </div>
        `
    });
};




export const sendEmail = async ({
    to,
    subject,
    html
}) => {

    await transporter.sendMail({
        from: process.env.SMTP_USER,
        to,
        subject,
        html
    });
};