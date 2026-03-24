import SwiftUI
import AVFoundation

struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onScan = { code in
            onScan(code)
        }
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}

    final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onScan: ((String) -> Void)?
        private var captureSession: AVCaptureSession?
        private var didFire = false

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black

            let session = AVCaptureSession()

            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else {
                return
            }
            session.addInput(input)

            let output = AVCaptureMetadataOutput()
            if session.canAddOutput(output) {
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                output.metadataObjectTypes = [.qr]
            }

            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.frame = view.bounds
            preview.videoGravity = .resizeAspectFill
            view.layer.addSublayer(preview)

            // Overlay with cutout
            let overlay = UIView(frame: view.bounds)
            overlay.backgroundColor = UIColor.black.withAlphaComponent(0.5)
            overlay.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            view.addSubview(overlay)

            let side = min(view.bounds.width, view.bounds.height) * 0.65
            let cutout = CGRect(
                x: (view.bounds.width - side) / 2,
                y: (view.bounds.height - side) / 2 - 40,
                width: side,
                height: side
            )
            let path = UIBezierPath(rect: overlay.bounds)
            path.append(UIBezierPath(roundedRect: cutout, cornerRadius: 16).reversing())
            let mask = CAShapeLayer()
            mask.path = path.cgPath
            overlay.layer.mask = mask

            // Corner markers
            let cornerLayer = CAShapeLayer()
            cornerLayer.strokeColor = UIColor.systemIndigo.cgColor
            cornerLayer.fillColor = UIColor.clear.cgColor
            cornerLayer.lineWidth = 4
            cornerLayer.lineCap = .round
            let cornerPath = UIBezierPath()
            let r: CGFloat = cutout.origin.x
            let b: CGFloat = cutout.origin.y
            let w: CGFloat = side
            let cl: CGFloat = 30
            // top-left
            cornerPath.move(to: CGPoint(x: r, y: b + cl))
            cornerPath.addLine(to: CGPoint(x: r, y: b))
            cornerPath.addLine(to: CGPoint(x: r + cl, y: b))
            // top-right
            cornerPath.move(to: CGPoint(x: r + w - cl, y: b))
            cornerPath.addLine(to: CGPoint(x: r + w, y: b))
            cornerPath.addLine(to: CGPoint(x: r + w, y: b + cl))
            // bottom-left
            cornerPath.move(to: CGPoint(x: r, y: b + w - cl))
            cornerPath.addLine(to: CGPoint(x: r, y: b + w))
            cornerPath.addLine(to: CGPoint(x: r + cl, y: b + w))
            // bottom-right
            cornerPath.move(to: CGPoint(x: r + w - cl, y: b + w))
            cornerPath.addLine(to: CGPoint(x: r + w, y: b + w))
            cornerPath.addLine(to: CGPoint(x: r + w, y: b + w - cl))
            cornerLayer.path = cornerPath.cgPath
            view.layer.addSublayer(cornerLayer)

            captureSession = session

            DispatchQueue.global(qos: .userInitiated).async {
                session.startRunning()
            }
        }

        nonisolated func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            MainActor.assumeIsolated {
                guard !didFire,
                      let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                      let value = object.stringValue else {
                    return
                }
                didFire = true
                captureSession?.stopRunning()
                let impact = UIImpactFeedbackGenerator(style: .medium)
                impact.impactOccurred()
                onScan?(value)
            }
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            captureSession?.stopRunning()
        }
    }
}
