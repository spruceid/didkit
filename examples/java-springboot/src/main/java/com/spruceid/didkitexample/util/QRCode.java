package com.spruceid.didkitexample.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public class QRCode {
    public static final QRCodeWriter barcodeWriter = new QRCodeWriter();

    public static BufferedImage generateImage(String barcodeText) throws Exception {
        final BitMatrix bitMatrix = barcodeWriter.encode(barcodeText, BarcodeFormat.QR_CODE, 512, 512);
        return MatrixToImageWriter.toBufferedImage(bitMatrix);
    }

    public static String imageToBase64(BufferedImage image) throws IOException {
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        ImageIO.write(image, "png", os);
        return Base64.getEncoder().encodeToString(os.toByteArray());
    }

    public static ModelAndView getModelAndView(String content) throws Exception {
        final ModelAndView mav = new ModelAndView("qrcode");
        final BufferedImage image = QRCode.generateImage(content);
        final String base64 = QRCode.imageToBase64(image);
        mav.addObject("qrcode", base64);
        return mav;
    }
}
