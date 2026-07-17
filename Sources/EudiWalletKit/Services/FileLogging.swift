/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Code taken from package "https://github.com/crspybits/swift-log-file"
import Logging
import Foundation
// Adapted from https://nshipster.com/textoutputstream/
private final class LockedFileSink: @unchecked Sendable {
	private let fileHandle: FileHandle
	private let lock = NSLock()

	init(fileHandle: FileHandle) {
		self.fileHandle = fileHandle
	}

	func write(_ data: Data) {
		lock.withLock {
			fileHandle.seekToEndOfFile()
			fileHandle.write(data)
		}
	}
}

private final class FileSinkRegistry: @unchecked Sendable {
	static let shared = FileSinkRegistry()
	private let lock = NSLock()
	private var sinks: [String: LockedFileSink] = [:]

	private init() {}

	func sink(for url: URL) throws -> LockedFileSink {
		try lock.withLock {
			let key = url.standardizedFileURL.path
			if let sink = sinks[key] { return sink }
			if !FileManager.default.fileExists(atPath: key) {
				guard FileManager.default.createFile(atPath: key, contents: nil, attributes: nil) else {
					throw FileHandlerOutputStream.StreamError.couldNotCreateFile
				}
			}
			let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: key))
			let sink = LockedFileSink(fileHandle: handle)
			sinks[key] = sink
			return sink
		}
	}
}

struct FileHandlerOutputStream: TextOutputStream, Sendable {
    enum StreamError: Error {
        case couldNotCreateFile
    }

	private let sink: LockedFileSink
    let encoding: String.Encoding

	init(localFile url: URL, encoding: String.Encoding = .utf8) throws {
		self.sink = try FileSinkRegistry.shared.sink(for: url)
        self.encoding = encoding
    }

	mutating func write(_ string: String) {
		if let data = string.data(using: encoding) {
			sink.write(data)
		}
    }
}

public struct FileLogging {
    let stream: FileHandlerOutputStream
    private var localFile: URL

    public init(to localFile: URL) throws {
        self.stream = try FileHandlerOutputStream(localFile: localFile)
        self.localFile = localFile
    }

    public func handler(label: String) -> FileLogHandler {
        return FileLogHandler(label: label, fileLogger: self)
    }

    public static func logger(label: String, localFile url: URL) throws -> Logger {
        let logging = try FileLogging(to: url)
        return Logger(label: label, factory: logging.handler)
    }
}

// Adapted from https://github.com/apple/swift-log.git

/// `FileLogHandler` is a simple implementation of `LogHandler` for directing
/// `Logger` output to a local file. Appends log output to this file, even across constructor calls.
public struct FileLogHandler: LogHandler {
    private let stream: FileHandlerOutputStream
    private var label: String

    public var logLevel: Logger.Level = .info

    private var prettyMetadata: String?
    public var metadata = Logger.Metadata() {
        didSet {
            self.prettyMetadata = self.prettify(self.metadata)
        }
    }

    public subscript(metadataKey metadataKey: String) -> Logger.Metadata.Value? {
        get {
            return self.metadata[metadataKey]
        }
        set {
            self.metadata[metadataKey] = newValue
        }
    }

    public init(label: String, fileLogger: FileLogging) {
        self.label = label
        self.stream = fileLogger.stream
    }

    public init(label: String, localFile url: URL) throws {
        self.label = label
        self.stream = try FileHandlerOutputStream(localFile: url)
    }

    public func log(event: LogEvent) {
        let prettyMetadata = event.metadata?.isEmpty ?? true
            ? self.prettyMetadata
            : self.prettify(self.metadata.merging(event.metadata!, uniquingKeysWith: { _, new in new }))

        var stream = self.stream
        stream.write("\(self.timestamp()) \(event.level) \(self.label) :\(prettyMetadata.map { " \($0)" } ?? "") \(event.message)\n")
    }

    private func prettify(_ metadata: Logger.Metadata) -> String? {
        return !metadata.isEmpty ? metadata.map { "\($0)=\($1)" }.joined(separator: " ") : nil
    }

	private func timestamp() -> String {
		let formatter = ISO8601DateFormatter()
		formatter.formatOptions = [.withInternetDateTime]
		return formatter.string(from: Date())
	}
}
