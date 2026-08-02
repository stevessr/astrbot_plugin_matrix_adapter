import io


class SASVerificationDisplayQRMixin:
    @staticmethod
    def _build_terminal_qr(data: bytes) -> str | None:
        try:
            import qrcode
        except Exception:
            return None

        qr = qrcode.QRCode(border=1)
        qr.add_data(data)
        qr.make(fit=True)

        output = io.StringIO()
        qr.print_ascii(out=output, invert=True)
        return output.getvalue().strip("\n")
