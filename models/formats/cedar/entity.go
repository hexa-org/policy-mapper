package cedar

// This is from https://github.com/iann0036/polai/entitystore.go
import (
    "bufio"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "reflect"

    "golang.org/x/exp/maps"
)

type rawEntity struct {
    Uid          string                      `json:"uid"`
    LowerParents []string                    `json:"parents"`
    Attrs        map[string]interface{}      `json:"attrs"`
    EntityId     *complexEntityName          `json:"EntityId"`
    Identifier   *complexEntityName          `json:"Identifier"`
    Parents      []complexEntityName         `json:"Parents"`
    Attributes   map[string]complexAttribute `json:"Attributes"`
}

type complexEntityName struct {
    EntityID   string `json:"EntityId"`
    EntityType string `json:"EntityType"`
}

type complexAttribute struct {
    String  *string                 `json:"String"`
    Long    *int64                  `json:"Long"`
    Boolean *bool                   `json:"Boolean"`
    Record  *map[string]interface{} `json:"Record"`
    Set     *[]interface{}          `json:"Set"`
}

type Entity struct {
    Identifier string
    Parents    []string
    Attributes []Attribute
}

type Attribute struct {
    Name         string
    StringValue  *string
    LongValue    *int64
    BooleanValue *bool
    RecordValue  *map[string]interface{}
    SetValue     *[]interface{}
}

// EntityStore represents the complete set of known entities within the system.
type EntityStore struct {
    r        *bufio.Reader
    entities *[]Entity
}

// NewEntityStore returns a new instance of EntityStore.
func NewEntityStore(r io.Reader) *EntityStore {
    return &EntityStore{r: bufio.NewReader(r)}
}

// SetEntities overrides all entities.
func (e *EntityStore) SetEntities(r io.Reader) {
    e.r = bufio.NewReader(r)
    e.entities = nil
}

// GetEntities retrieves all entities.
func (e *EntityStore) GetEntities() ([]Entity, error) {
    if e.entities == nil {
        b, err := ioutil.ReadAll(e.r)
        if err != nil && err != io.EOF {
            return nil, err
        }

        var rawEntities []rawEntity
        if err := json.Unmarshal(b, &rawEntities); err != nil {
            return nil, fmt.Errorf("error parsing entity store json, %s", err.Error())
        }

        var entities []Entity
        for _, rawEntity := range rawEntities {
            if rawEntity.EntityId != nil {
                rawEntity.Identifier = rawEntity.EntityId
            }

            if rawEntity.Uid != "" {
                var attributes []Attribute
                for attrName, attrVal := range rawEntity.Attrs {
                    attribute := Attribute{
                        Name: attrName,
                    }

                    switch attrVal.(type) {
                    case int:
                        val := int64(attrVal.(int))
                        attribute.LongValue = &val
                    case int64:
                        val := attrVal.(int64)
                        attribute.LongValue = &val
                    case float64:
                        val := int64(attrVal.(float64))
                        attribute.LongValue = &val
                    case string:
                        val := attrVal.(string)
                        attribute.StringValue = &val
                    case bool:
                        val := attrVal.(bool)
                        attribute.BooleanValue = &val
                    case map[string]interface{}:
                        val := attrVal.(map[string]interface{})
                        attribute.RecordValue = &val
                    case []interface{}:
                        val := attrVal.([]interface{})
                        attribute.SetValue = &val
                    default:
                        return nil, fmt.Errorf("unknown type in attribute block: %v (%s)", attrVal, reflect.TypeOf(attrVal).String())
                    }

                    attributes = append(attributes, attribute)
                }

                entities = append(entities, Entity{
                    Identifier: rawEntity.Uid,
                    Parents:    rawEntity.LowerParents,
                    Attributes: attributes,
                })
            } else if rawEntity.Identifier != nil {
                b, _ := json.Marshal(rawEntity.Identifier.EntityID)
                entity := Entity{
                    Identifier: fmt.Sprintf("%s::%s", rawEntity.Identifier.EntityType, string(b)),
                }

                for _, parent := range rawEntity.Parents {
                    b, _ := json.Marshal(parent.EntityID)
                    entity.Parents = append(entity.Parents, fmt.Sprintf("%s::%s", parent.EntityType, string(b)))
                }

                for attrName, attrVal := range rawEntity.Attributes {
                    // TODO: validate only one field set
                    entity.Attributes = append(entity.Attributes, Attribute{
                        Name:         attrName,
                        BooleanValue: attrVal.Boolean,
                        StringValue:  attrVal.String,
                        LongValue:    attrVal.Long,
                        RecordValue:  attrVal.Record,
                        SetValue:     attrVal.Set,
                    })
                }

                entities = append(entities, entity)
            } else {
                return nil, fmt.Errorf("no entity identifier found in entity list item")
            }
        }

        e.entities = &entities
    }

    return *e.entities, nil
}

// GetEntityDescendents retrieves all entities that match or are descendents of those passed in.
func (e *EntityStore) GetEntityDescendents(parents []string) ([]Entity, error) {
    baseEntities, err := e.GetEntities()
    if err != nil {
        return nil, err
    }

    foundEntities := map[string]Entity{} // using map[string] for dedup purposes
    i := 0
    for i < len(parents) {
        parent := parents[i]
        for _, baseEntity := range baseEntities {
            for _, baseEntityParent := range baseEntity.Parents {
                if baseEntityParent == parent && !contains(parents, baseEntity.Identifier) {
                    parents = append(parents, baseEntity.Identifier)
                }
            }
            if baseEntity.Identifier == parent {
                foundEntities[baseEntity.Identifier] = baseEntity
            }
        }
        i++
    }

    return maps.Values(foundEntities), nil
}

func contains(s []string, str string) bool {
    for _, v := range s {
        if v == str {
            return true
        }
    }

    return false
}

func containsEntity(list []Entity, id string) bool {
    for _, v := range list {
        if v.Identifier == id {
            return true
        }
    }

    return false
}
