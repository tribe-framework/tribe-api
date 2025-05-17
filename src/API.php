<?php
namespace Tribe;

use JetBrains\PhpStorm\NoReturn;
use alsvanzelf\jsonapi\CollectionDocument;
use alsvanzelf\jsonapi\ResourceDocument;
use alsvanzelf\jsonapi\MetaDocument;

class API {

    private $response;
    private $request;
    public $requestBody;

    public function __construct()
    {
        $this->requestBody = \json_decode(\file_get_contents('php://input'), 1) ?? [];

        $this->config = new \Tribe\Config;
        $this->core = new \Tribe\Core;
        $this->auth = new \Tribe\Auth;
        $this->sql = new \Tribe\MySQL;

        $this->url_parts = explode('/', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        $this->type = (string) ($this->url_parts[2] ?? '');

        if (!is_numeric($this->url_parts[3] ?? false)) {
            $this->id = (int) $this->core->getAttribute(array('type'=>$this->type, 'slug'=>$this->url_parts[3]), 'id');
        } else {
            $this->id = (int) ($this->url_parts[3] ?? 0);
        }

    }


    /**
     * Validates API key authentication and handles exceptions
     * @param array $api_keys All your API keys stored in a variable
     * @return void
     */
    private function validateApiKey($api_keys) {
        // Get the API key from the request headers
        $request_api_key = $this->auth()['token'] ?? $_SERVER['HTTP_X_API_KEY'];
        
        $request_domain = parse_url((isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : ''), PHP_URL_HOST);
        
        // Get the junction domain
        $junction_domain = parse_url($_ENV['JUNCTION_URL'], PHP_URL_HOST);
        
        // Get the web domain
        $web_domain = parse_url($_ENV['WEB_URL'], PHP_URL_HOST);
        
        // Extract base domains for comparison
        $request_base_domain = $this->getBaseDomain($request_domain);
        $web_base_domain = $this->getBaseDomain($web_domain);
        
        // Exception cases where authentication is not required
        if (
            // Case 1: Same domain as JUNCTION_URL
            $request_domain === $junction_domain ||
            // Case 2: Same base/parent domain as WEB_URL
            $request_base_domain === $web_base_domain ||
            // Case 3: Environment is not production
            $_ENV['ENV'] !== 'prod' ||
            // Case 4: API Key exists and is valid
            in_array($request_api_key, $api_keys)
        ) {
            return;
        }
        
        // If API key is missing
        else if (!$request_api_key) {
            $error = [
                'errors' => [[
                    'status' => '401',
                    'title' => 'Unauthorized',
                    'detail' => 'API key is missing. This resource is only available to authorised applications.'
                ]]
            ];
            $this->json($error)->send(401);
        }
        
        // If API key is invalid
        else {
            $error = [
                'errors' => [[
                    'status' => '403',
                    'title' => 'Forbidden',
                    'detail' => 'Invalid API key.'
                ]]
            ];
            $this->json($error)->send(403);
        }
    }

    /**
     * Helper function to extract base domain from a domain string
     * @param string $domain Full domain name
     * @return string Base domain
     */
    private function getBaseDomain($domain) {
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            return implode('.', array_slice($parts, -2));
        }
        return $domain;
    }

    /**
     * Process linked modules for an object and add relationships to the document
     * 
     * @param ResourceDocument $document The document to add relationships to
     * @param array $object The object containing module data
     * @param array $linked_modules The linked modules configuration
     * @param array|null $related_objects_core Optional pre-fetched related objects
     * @param array|null $rojt Optional lookup table for slug-based lookups
     * @param array|null $id_rojt Optional lookup table for ID-based lookups
     * @return ResourceDocument The document with added relationships
     */
    private function processLinkedModules(
        ResourceDocument $document, 
        array $object, 
        array $linked_modules, 
        array $related_objects_core = null, 
        array $rojt = null,
        array $id_rojt = null
    ) {
        foreach ($linked_modules as $module_key => $module_type) {
            if (array_key_exists($module_key, $object)) {
                $value = $object[$module_key];
                
                // Skip if the value is empty
                if (empty($value)) {
                    continue;
                }
                
                // If we don't have pre-fetched related objects, fetch them now
                if ($related_objects_core === null) {
                    // Determine the query format based on the value type
                    if (is_array($value)) {
                        // Check if it's an array of numeric IDs
                        if (is_numeric($value[0] ?? '')) {
                            // Array of IDs: [23, 24, 25] or ["23", "24", "25"]
                            $related_objects = $this->core->getObjects(implode(',', $value));
                        } else {
                            // Array of slugs: ["slug1", "slug2", "slug3"]
                            $query_params = [];
                            foreach ($value as $slug) {
                                $query_params[] = [
                                    'type' => $module_type,
                                    'slug' => $slug
                                ];
                            }
                            $related_objects = $this->core->getObjects($query_params);
                        }
                    } else if (is_string($value)) {
                        // Check if it's a comma-separated list of IDs
                        if (strpos($value, ',') !== false && is_numeric(trim(explode(',', $value)[0]))) {
                            // Comma-separated IDs: "23, 24, 25"
                            $related_objects = $this->core->getObjects($value);
                        } else if (is_numeric($value)) {
                            // Single numeric ID: "23" or 23
                            $related_objects = $this->core->getObjects($value);
                        } else {
                            // Single slug: "slug1"
                            $related_objects = [$this->core->getObject([
                                'type' => $module_type,
                                'slug' => $value
                            ])];
                        }
                    } else if (is_int($value)) {
                        $related_objects = [$this->core->getObject($value)];
                    }
                    
                    // Add relationships if related objects were found
                    if (!empty($related_objects)) {
                        // Create an array of relationship objects
                        $relationships = [];
                        
                        foreach($related_objects as $related_object) {
                            if ($related_object && $related_object['id'] != $object['id']) {
                                $ojt = new ResourceDocument($module_type, $related_object['id']);
                                $ojt->add('modules', $related_object);
                                $ojt->add('slug', $related_object['slug']);
                                $relationships[] = $ojt;
                            }
                        }
                        
                        // Add all relationships at once as a collection
                        if (!empty($relationships)) {
                            $document->addRelationship($module_key, $relationships);
                        }
                    }
                } 
                // Use pre-fetched related objects (for collection documents)
                else {
                    $items_to_process = [];
                    
                    // Convert the value to an array of items to process
                    if (is_array($value)) {
                        $items_to_process = $value;
                    } else if (is_string($value) && strpos($value, ',') !== false) {
                        // Handle comma-separated values
                        $items_to_process = array_map('trim', explode(',', $value));
                    } else {
                        $items_to_process = [$value];
                    }
                    
                    // Create an array of relationship objects
                    $relationships = [];
                    
                    foreach ($items_to_process as $item) {
                        // For numeric IDs, look up directly in id_rojt
                        if (is_numeric($item)) {
                            $related_id = (int)$item;
                            if (isset($id_rojt[$related_id]) && $related_id != $object['id']) {
                                $related_object = $id_rojt[$related_id];
                                $ojt = new ResourceDocument($module_type, $related_id);
                                $ojt->add('modules', $related_object);
                                $ojt->add('slug', $related_object['slug'] ?? '');
                                $relationships[] = $ojt;
                            }
                        } 
                        // For slugs, use the slug-based lookup table
                        else if (isset($rojt[$module_type][$item])) {
                            $related_id = $rojt[$module_type][$item];
                            if ($related_id && $related_id != $object['id'] && isset($related_objects_core[$related_id])) {
                                $ojt = new ResourceDocument($module_type, $related_id);
                                $ojt->add('modules', $related_objects_core[$related_id]);
                                $ojt->add('slug', $item);
                                $relationships[] = $ojt;
                            }
                        }
                    }
                    
                    // Add all relationships at once as a collection
                    if (!empty($relationships)) {
                        $document->addRelationship($module_key, $relationships);
                    }
                }
            }
        }
        
        return $document;
    }

    public function jsonAPI($version = '1.1') {

        /* REVIEW AND INCLUDE THIS CODE
        $api_keys = [];
        if ($api_ids = $this->core->getIDs(array('type'=>'apikey_record'))) {
            $api_keys = array_column(
                $this->core->getObjects($api_ids), 
                'apikey'
            );
        }

        $this->validateApiKey($api_keys ?? array($_ENV['TRIBE_API_SECRET_KEY']));
        */

        if ($version == '1.1') {
            
            $linked_modules = $this->config->getTypeLinkedModules($this->type);

            if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
                if ($this->id) {
                    if ($this->core->deleteObject($this->id)) {
                        $document = new ResourceDocument();
                        $document->sendResponse();
                    }
                    else {
                        $this->send(404);
                        die();
                    }
                }
                else {
                    $this->send(404);
                    die();
                }
            }

            else if ($_SERVER['REQUEST_METHOD'] === 'PATCH') {
                $object = $this->requestBody;

                if ($this->type == 'webapp') {

                    $this->pushTypesObject($object);
                    $this->getTypesObject();

                } else {

                    $object = array_merge($this->core->getObject($object['data']['id']), $object['data'], $object['data']['attributes']['modules']);
                    unset($object['attributes']);
                    
                    $object = $this->core->getObject($this->core->pushObject($object));

                    $document = new ResourceDocument($this->type, $object['id']);
                    $document->add('modules', $object);
                    $document->add('slug', $object['slug']);

                    if ($linked_modules != []) {
                        $document = $this->processLinkedModules($document, $object, $linked_modules);
                    }

                    $document->sendResponse();
                }
            }

            else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $object = $this->requestBody;

                if ($this->type == 'webapp') {

                    $this->pushTypesObject($object);
                    $this->getTypesObject();

                } else {
                    
                    $object = array_merge($object['data'], $object['data']['attributes']['modules']);
                    unset($object['attributes']);

                    if ($object['type'] == 'user')
                        $object['user_id'] = $this->auth->getUniqueUserID();

                    $object = $this->core->getObject($this->core->pushObject($object));

                    $document = new ResourceDocument($this->type, $object['id']);
                    $document->add('modules', $object);
                    $document->add('slug', $object['slug']);

                    if ($linked_modules != []) {
                        $document = $this->processLinkedModules($document, $object, $linked_modules);
                    }

                    $document->sendResponse();
                }
            }

            else {

                if ($this->type == 'webapp') {
                    $this->getTypesObject();
                }

                else if (($this->type ?? false) && !($this->id ?? false)) {

                    //PAGINATION
                    $limit = "0, 25";
                    if ($_GET['page']['limit'] != '-1') {
                        if (!($_GET['page']['offset'] ?? false))
                            $_GET['page']['offset'] = 0;
                        if (!($_GET['page']['limit'] ?? false))
                            $_GET['page']['limit'] = 25;

                        if (($_GET['page']['limit'] ?? false) !== null && ($_GET['page']['offset'] ?? false) !== null)
                            $limit = "{$_GET['page']['offset']}, {$_GET['page']['limit']}";
                        else if (($_GET['page']['limit'] ?? false) !== null)
                            $limit = $_GET['page']['limit'];
                    } else {
                        $limit = "";
                    }

                    //SORTING
                    if ($_GET['sort'] ?? false) {
                        if ($_GET['sort'] == '(random)') {
                            $sort_field = '(random)';
                            $sort_order = 'DESC';
                        }
                        else {
                            $sort_arr = array_map('trim', explode(',', $_GET['sort']));
                            $sort_field = $sort_order = array();

                            foreach ($sort_arr as $val) {
                                if (substr($val, 0, 1) == '-') {
                                    $sort_field[] = substr($val, 1, strlen($val));
                                    $sort_order[] = 'DESC';
                                }
                                else {
                                    $sort_field[] = $val;
                                    $sort_order[] = 'ASC';
                                }
                            }
                        }
                    }
                    else {
                        $sort_field = 'id';
                        $sort_order = 'DESC';
                    }
                    
                    //getting IDs
                    if ($this->ids = $this->core->getIDs(
                            $search_array = array_merge(
                                ($_GET['filter'] ?? []), 
                                ($_GET['modules'] ?? []), 
                                array('type'=>$this->type)
                            ), 
                            $limit,
                            $sort_field, 
                            $sort_order,
                            $show_public_objects_only = (($_GET['show_public_objects_only'] === 'false' || $_GET['show_public_objects_only'] === false) ? boolval(false) : boolval(true)), 
                            $ignore_ids = ($_GET['ignore_ids'] ?? []), 
                            $show_partial_search_results = (($_GET['filter'] ?? false) ? boolval(true) : boolval(false)),
                            false, 'LIKE', 'OR', 'AND', ($_GET['range'] ?? [])
                        ))
                    {
                        $objectr = $this->core->getObjects($this->ids);
                        $objects = [];
                        
                        //to sort accurately
                        foreach ($this->ids as $this->idr) {
                            $objects[] = $objectr[$this->idr['id']];
                        }

                        $i = 0;
                        $related_objects_meta = [];
                        $related_objects_core = [];
                        $rojt = [];
                        foreach ($objects as $object) {
                            $documents[$i] = new ResourceDocument($this->type, $object['id']);
                            $documents[$i]->add('modules', $object);
                            $documents[$i]->add('slug', $object['slug']);

                            if ($linked_modules != []) {
                                foreach ($linked_modules as $module_key => $module_type) {
                                    if (array_key_exists($module_key, $object)) {
                                        $value = $object[$module_key];
                                        
                                        // Skip if the value is empty
                                        if (empty($value)) {
                                            continue;
                                        }
                                        
                                        // Process different input formats
                                        if (is_array($value)) {
                                            // Handle array of values (could be IDs or slugs)
                                            foreach ($value as $item) {
                                                if (is_numeric($item)) {
                                                    // It's an ID
                                                    $related_objects_meta[] = [
                                                        'id' => (int)$item,
                                                        'module' => $module_key,
                                                        'type' => $module_type
                                                    ];
                                                } else {
                                                    // It's a slug
                                                    $related_objects_meta[] = [
                                                        'type' => $module_type,
                                                        'module' => $module_key,
                                                        'slug' => $item,
                                                    ];
                                                }
                                            }
                                        } else if (is_string($value) && strpos($value, ',') !== false) {
                                            // Handle comma-separated string
                                            $items = array_map('trim', explode(',', $value));
                                            foreach ($items as $item) {
                                                if (is_numeric($item)) {
                                                    // It's an ID
                                                    $related_objects_meta[] = [
                                                        'id' => (int)$item,
                                                        'module' => $module_key,
                                                        'type' => $module_type
                                                    ];
                                                } else {
                                                    // It's a slug
                                                    $related_objects_meta[] = [
                                                        'type' => $module_type,
                                                        'module' => $module_key,
                                                        'slug' => $item,
                                                    ];
                                                }
                                            }
                                        } else {
                                            // Handle single value (could be ID or slug)
                                            if (is_numeric($value)) {
                                                // It's an ID
                                                $related_objects_meta[] = [
                                                    'id' => (int)$value,
                                                    'module' => $module_key,
                                                    'type' => $module_type
                                                ];
                                            } else {
                                                // It's a slug
                                                $related_objects_meta[] = [
                                                    'type' => $module_type,
                                                    'module' => $module_key,
                                                    'slug' => $value,
                                                ];
                                            }
                                        }
                                    }
                                }
                            }

                            $i++;
                        }

                        if ($linked_modules != [] && !empty($related_objects_meta)) {
                            // Fetch all related objects at once
                            $related_objects_core = $this->core->getObjects($related_objects_meta);
                            
                            // Build lookup tables for both slug-based and ID-based lookups
                            $rojt = [];
                            $id_rojt = [];
                            
                            foreach ($related_objects_core as $related_object) {
                                // For slug-based lookups
                                if (isset($related_object['slug'])) {
                                    $rojt[$related_object['type']][$related_object['slug']] = $related_object['id'];
                                }
                                
                                // For ID-based lookups - store the object directly by ID
                                $id_rojt[$related_object['id']] = $related_object;
                            }
                            
                            $i = 0;
                            // Process each object with the fetched related objects
                            foreach ($objects as $object) {
                                // Pass both lookup tables to processLinkedModules
                                $documents[$i] = $this->processLinkedModules(
                                    $documents[$i], 
                                    $object, 
                                    $linked_modules, 
                                    $related_objects_core, 
                                    $rojt,
                                    $id_rojt
                                );
                                $i++;
                            }
                        }

                        $document = CollectionDocument::fromResources(...$documents);

                        $totalObjectsCount= $this->core->getIDsTotalCount(
                            $search_array = array_merge(
                                ($_GET['filter'] ?? []), 
                                ($_GET['modules'] ?? []), 
                                array('type'=>$this->type)
                            ), 
                            $limit,
                            $sort_field, 
                            $sort_order,
                            $show_public_objects_only = (($_GET['show_public_objects_only'] === 'false' || $_GET['show_public_objects_only'] === false) ? boolval(false) : boolval(true)), 
                            $ignore_ids = ($_GET['ignore_ids'] ?? []), 
                            $show_partial_search_results = (($_GET['filter'] ?? false) ? boolval(true) : boolval(false)),
                            false, 'LIKE', 'OR', 'AND', ($_GET['range'] ?? [])
                        );

                        $document->addMeta('total_objects', $totalObjectsCount);
                        //$document['meta'] = array('total_objects', $totalObjectsCount);

                        $document->sendResponse();
                    } 

                    else {
                        $documents = array();
                        $document = CollectionDocument::fromResources(...$documents);
                        $document->sendResponse();
                    }
                }

                else if (($this->type ?? false) && ($this->id ?? false)) {

                    if ($object = $this->core->getObject($this->id)) {
                        $document = new ResourceDocument($this->type, $object['id']);
                        $document->add('modules', $object);
                        $document->add('slug', $object['slug']);

                        if ($linked_modules != []) {
                            $document = $this->processLinkedModules($document, $object, $linked_modules);
                        }

                        $document->sendResponse();
                    } else {
                        $this->send(404);
                        die();
                    }
                }

                else {
                    $this->send(404);
                    die();
                }
            }
        }

    }

    public function pushTypesObject($object) {
        $folder_path = TRIBE_ROOT . '/uploads/types';
        if (!is_dir($folder_path)) {
            mkdir($folder_path);
        }
        $types_file_path = $folder_path.'/types-'.time().'.json';
        file_put_contents($types_file_path, json_encode($object['data']['attributes']['modules'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        unset($object['attributes']);
    }

    public function getTypesObject() {
        $object = $this->config->getTypes();

        foreach ($object as $key => $value) {
            $object[$key]['total_objects'] = $this->core->getTypeObjectsCount($key);
        }

        $sizeRaw = $this->core->executeShellCommand('du -s '.TRIBE_ROOT . '/uploads');
        $objectsCount = $this->sql->executeSQL("SELECT COUNT(*) AS `count` FROM `data`");
        $object['webapp']['size_in_gb'] = number_format((float)(explode(' ', $sizeRaw)[0]/1024/1024), 2, '.', '');
        $object['webapp']['total_objects'] = $objectsCount[0]['count'];

        $document = new ResourceDocument($this->type, 0);
        $document->add('modules', $object);
        $document->add('slug', ($object['slug'] ?? 'webapp'));
        $document->sendResponse();
    }

    /**
     * allow access to api only if the request meets certain permissions
     * this function fetches bearer_token from auth header and verifies the
     * jwt. Request only goes through if "allowed_role" matches the role
     * on token.
     */
    public function auth(): array
    {
        $auth_head = $_SERVER['HTTP_AUTHORIZATION'] ?? null;

        if (!$auth_head) {
            return ["Bearer" => null];
        }

        $auth_head = \explode(' ', $auth_head);

        if ($auth_head[0] == "Bearer") {
            $auth_head = [ "token" => $auth_head[1] ?? "" ];
        }

        return $auth_head;
    }

    /**
     * returns the request body as an array
     */
    public function body(): array
    {
        return $this->requestBody;
    }

    /**
     * encodes passed data as a json that can be sent over network
     */
    public function json($data): Api
    {
        $encodeOptions =  JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PARTIAL_OUTPUT_ON_ERROR;
        $this->response = json_encode($data, $encodeOptions);
        return $this;
    }

    /**
     * sets http code to response and responds to the request
     * @param int $status_code
     */
    #[NoReturn]
    public function send(int $status_code = 200)
    {
        // set header and status code
        header('Content-Type: application/vnd.api+json');
        http_response_code($status_code);

        echo $this->response;
        die();
    }

    /**
     * validates request method for API calls
     * @param ?string $reqMethod
     * @return bool|string
     */
    public function method(string $reqMethod = null)
    {
        if (!$reqMethod) {
            return strtolower($_SERVER['REQUEST_METHOD']);
        }

        $serverMethod = strtolower($_SERVER['REQUEST_METHOD']);
        $reqMethod = strtolower($reqMethod);

        return $serverMethod === $reqMethod;
    }

    /*
     * Servers MUST respond with a 415 Unsupported Media Type status code
     * if a request specifies the header Content-Type: application/vnd.api+json
     * with any media type parameters.
     */
    public function isValidJsonRequest()
    {
        $error = 0;
        $requestHeaders = $this->getRequestHeaders();

        if (is_array($requestHeaders['Content-Type']) && in_array('application/vnd.api+json', $requestHeaders['Content-Type'])) {
            //In some responses Content-type is an array
            $error = 1;

        } else if (strstr($requestHeaders['Content-Type'], 'application/vnd.api+json')) {
            $error = 1;
        }
        if ($error) {
            $this->send(415);
            die();
        } else {
            return true;
        }

    }

    /*
     * This small helper function generates RFC 4122 compliant Version 4 UUIDs.
     */
    public function guidv4($data = null)
    {
        // Generate 16 bytes (128 bits) of random data or use the data passed into the function.
        $data = $data ?? random_bytes(16);
        assert(strlen($data) == 16);

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        // Output the 36 character UUID.
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public function exposeTribeApi(array $url_parts, array $all_types): void
    {
        require __DIR__."/../v1/handler.php";
        return;
    }
}