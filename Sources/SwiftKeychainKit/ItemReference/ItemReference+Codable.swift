private import Foundation

extension ItemReference: Codable where ItemClass: ItemReferenceTaggable {
    private enum CodingKeys: String, CodingKey {
        case classTag
        case persistentReferenceData
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let classTag = try container.decode(ItemReferenceClassTag.self, forKey: .classTag)
        guard classTag == ItemClass.itemReferenceClassTag else {
            throw DecodingError.dataCorruptedError(
                forKey: .classTag,
                in: container,
                debugDescription: "Item class mismatch: expected \(ItemClass.itemReferenceClassTag), found \(classTag)"
            )
        }

        persistentReferenceData = try container.decode(Data.self, forKey: .persistentReferenceData)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ItemClass.itemReferenceClassTag, forKey: .classTag)
        try container.encode(persistentReferenceData, forKey: .persistentReferenceData)
    }
}
