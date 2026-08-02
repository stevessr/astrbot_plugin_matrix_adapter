"""Optional terminal QR rendering for Matrix SSO."""

import io


def _build_terminal_qr(data: str) -> str | None:
    """Build an ASCII QR code for terminal display.

    Returns None when qrcode dependency is unavailable.
    """
    try:
        import qrcode
    except Exception:
        return None

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)

    output = io.StringIO()
    qr.print_ascii(out=output, invert=True)
    return output.getvalue()
