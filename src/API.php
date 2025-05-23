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
    private $allowed_read_access_api_keys = [];
    private $allowed_full_access_api_keys = [];
    private $api_objects = [];

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

        // Load API keys
        $this->loadApiKeys();
        
        // Handle CORS for API requests
        $this->handleCors();
    }

    /**
     * Handle CORS headers for API requests
     * This method should be called early in the request lifecycle
     */
    private function handleCors() {
        // Get the request origin
        $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_HOST'] ?? '*';
        
        // Get the request method
        $request_method = $_SERVER['REQUEST_METHOD'];
        
        // Set CORS headers for all responses
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Max-Age: 86400"); // Cache preflight for 24 hours
        
        // Set allowed headers - include X-API-KEY explicitly
        header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-KEY, X-Requested-With, Accept, Origin");
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS");
        
        // Handle preflight OPTIONS request
        if ($request_method === 'OPTIONS') {
            // Just exit with 200 OK for preflight requests
            http_response_code(200);
            exit(0);
        }
        
        // Continue with the regular request processing
        return;
    }

    /**
     * Load API keys from the database
     */
    private function loadApiKeys() {
        $this->allowed_read_access_api_keys = $this->allowed_full_access_api_keys = [];
        $this->api_objects = []; // Store all API objects for domain validation
        
        if ($api_ids = $this->core->getIDs(array('type'=>'apikey_record'), "0, 25", 'id', 'DESC', false)) {
            $api_objects = $this->core->getObjects($api_ids);

            foreach ($api_objects as $api_object) {
                // Store the full API object for later use
                $this->api_objects[$api_object['apikey']] = $api_object;
                
                if (($api_object['content_privacy'] == 'public' || $api_object['content_privacy'] == 'private') && (($api_object['readonly'] ?? false) === false || $api_object['readonly'] == false))
                    $this->allowed_full_access_api_keys[] = $api_object['apikey'];
                else if ($api_object['content_privacy'] == 'public' || $api_object['content_privacy'] == 'private')
                    $this->allowed_read_access_api_keys[] = $api_object['apikey'];
            }
        }
    }

    /**
     * Validates API key authentication and handles exceptions
     * @return bool Whether the request is authorized
     */
    private function validateApiKey() {
        // Extract the token if it's in Bearer format
        $request_api_key = null;
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
        if ($auth_header && strpos($auth_header, 'Bearer ') === 0) {
            $request_api_key = substr($auth_header, 7);
        }
        
        // Get the request domain
        $request_domain = parse_url((isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : ''), PHP_URL_HOST);
        if (empty($request_domain)) {
            $request_domain = $_SERVER['HTTP_HOST'] ?? '';
        }
        
        // Get the instance slug from the environment
        $instance_slug = (explode('.', $request_domain)[0]) ?? '';
        
        // Check if the request is coming from a Junction domain
        $is_junction_domain = false;
        if (!empty($request_domain)) {
            $junction_domains = [
                "$instance_slug.junction.express",
                "$instance_slug.tribe.junction.express",
                "tribe.junction.express"
            ];
            
            foreach ($junction_domains as $domain) {
                if (strpos($request_domain, $domain) !== false) {
                    $is_junction_domain = true;
                    break;
                }
            }
        }
        
        // Check if the request is from localhost
        $is_localhost = in_array($request_domain, ['localhost', '127.0.0.1']) || 
                        strpos($request_domain, 'localhost:') === 0 || 
                        strpos($request_domain, '127.0.0.1:') === 0;
        
        // Get the request method
        $request_method = strtoupper($_SERVER['REQUEST_METHOD']);
        
        // Get the type configuration to check if API access is locked
        $typesJSON = $this->config->getTypes();
        $block_read_access_without_apikey = isset($typesJSON['block_read_access_without_apikey']) && $typesJSON['block_read_access_without_apikey'] === true;
        
        // Allow all operations for Junction domains
        if ($is_junction_domain) {
            return true;
        }

        // Check if API key is valid and has special permissions
        if ($request_api_key && isset($this->api_objects[$request_api_key])) {
            $api_object = $this->api_objects[$request_api_key];
            
            // Check for dev mode with localhost
            if (isset($api_object['devmode']) && $api_object['devmode'] === true && $is_localhost) {
                return true; // Allow all operations in dev mode from localhost
            }
            
            // Check for whitelisted domains
            if (!empty($api_object['whitelisted_domains'])) {
                $whitelisted_domains = array_map('trim', explode("\n", $api_object['whitelisted_domains']));
                
                foreach ($whitelisted_domains as $domain_pattern) {
                    // Convert wildcard pattern to regex
                    if (strpos($domain_pattern, '*') !== false) {
                        $pattern = '/^' . str_replace('*', '.*', preg_quote($domain_pattern, '/')) . '$/i';
                        if (preg_match($pattern, $request_domain)) {
                            // For read operations, any valid API key is sufficient
                            if ($request_method === 'GET') {
                                return true;
                            }
                            // For write operations, need full access API key
                            else if (in_array($request_method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
                                return in_array($request_api_key, $this->allowed_full_access_api_keys);
                            }
                        }
                    } 
                    // Exact domain match
                    else if (strtolower($domain_pattern) === strtolower($request_domain)) {
                        // For read operations, any valid API key is sufficient
                        if ($request_method === 'GET') {
                            return true;
                        }
                        // For write operations, need full access API key
                        else if (in_array($request_method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
                            return in_array($request_api_key, $this->allowed_full_access_api_keys);
                        }
                    }
                }
            }
        }
        
        // For read operations (GET)
        if ($request_method === 'GET') {
            // If API access is locked, require a valid API key
            //Webapp data cannot be accessed publicly
            if ($block_read_access_without_apikey || $this->type == 'webapp') {
                return in_array($request_api_key, $this->allowed_read_access_api_keys);
            } else {
                return true;
            }
        }
        
        // For write operations (POST, PUT, PATCH, DELETE)
        if (in_array($request_method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
            // Require a valid API key with full access
            return in_array($request_api_key, $this->allowed_full_access_api_keys);
        }
        
        // Default deny for unrecognized methods
        return false;
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
                    $related_objects = [];
                    
                    // Determine the query format based on the value type
                    if (is_array($value)) {
                        // Check if it's an array of numeric IDs
                        if (!empty($value) && is_numeric($value[0] ?? '')) {
                            // Array of IDs: [23, 24, 25] or ["23", "24", "25"]
                            $related_objects = $this->core->getObjects(implode(',', $value));
                        } else {
                            // Array of slugs: ["slug1", "slug2", "slug3"]
                            $query_params = [];
                            foreach ($value as $slug) {
                                if (!empty($slug)) {
                                    $query_params[] = [
                                        'type' => $module_type,
                                        'slug' => $slug
                                    ];
                                }
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
                            $obj = $this->core->getObject([
                                'type' => $module_type,
                                'slug' => $value
                            ]);
                            if ($obj) {
                                $related_objects = [$obj];
                            }
                        }
                    } else if (is_int($value)) {
                        $obj = $this->core->getObject($value);
                        if ($obj) {
                            $related_objects = [$obj];
                        }
                    }
                    
                    // Add relationships if related objects were found
                    if (!empty($related_objects)) {
                        // Create an array of relationship objects
                        $relationships = [];
                        $processed_ids = []; // Track already processed IDs
                        
                        foreach($related_objects as $related_object) {
                            if (empty($related_object) || !isset($related_object['id'])) {
                                continue;
                            }
                            
                            $related_id = $related_object['id'];
                            
                            // Skip if this is the same as the current object or already processed
                            if ($related_id == $object['id'] || isset($processed_ids[$related_id])) {
                                continue;
                            }
                            
                            // Mark as processed
                            $processed_ids[$related_id] = true;
                            
                            $ojt = new ResourceDocument($module_type, $related_id);
                            $ojt->add('modules', $related_object);
                            $ojt->add('slug', $related_object['slug'] ?? '');
                            $relationships[] = $ojt;
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
                    $processed_ids = []; // Track already processed IDs
                    
                    foreach ($items_to_process as $item) {
                        if (empty($item)) {
                            continue;
                        }
                        
                        // For numeric IDs, look up directly in id_rojt
                        if (is_numeric($item)) {
                            $related_id = (int)$item;
                            
                            // Skip if already processed, same as current object, or not found
                            if (isset($processed_ids[$related_id]) || 
                                $related_id == $object['id'] || 
                                !isset($id_rojt[$related_id])) {
                                continue;
                            }
                            
                            // Mark as processed
                            $processed_ids[$related_id] = true;
                            
                            $related_object = $id_rojt[$related_id];
                            $ojt = new ResourceDocument($module_type, $related_id);
                            $ojt->add('modules', $related_object);
                            $ojt->add('slug', $related_object['slug'] ?? '');
                            $relationships[] = $ojt;
                        } 
                        // For slugs, use the slug-based lookup table
                        else if (isset($rojt[$module_type][$item])) {
                            $related_id = $rojt[$module_type][$item];
                            
                            // Skip if already processed, invalid ID, or not found
                            if (isset($processed_ids[$related_id]) || 
                                !$related_id || 
                                $related_id == $object['id'] || 
                                !isset($related_objects_core[$related_id])) {
                                continue;
                            }
                            
                            // Mark as processed
                            $processed_ids[$related_id] = true;
                            
                            $ojt = new ResourceDocument($module_type, $related_id);
                            $ojt->add('modules', $related_objects_core[$related_id]);
                            $ojt->add('slug', $item);
                            $relationships[] = $ojt;
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
        // Validate API key for all requests
        if (!$this->validateApiKey()) {
            $error = [
                'errors' => [[
                    'status' => '403',
                    'title' => 'Forbidden',
                    'detail' => 'You do not have permission to access this resource. If your request is using an API key in production mode, make sure it is from a whitelisted domain. Use Junction to generate API keys and whitelist your domains.'
                ]]
            ];
            $this->json($error)->send(403);
            return;
        }

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
        // Set content type header
        header('Content-Type: application/vnd.api+json');
        
        // Set CORS headers again to ensure they're included in all responses
        $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_HOST'] ?? '*';
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Credentials: true");
        
        // Set the HTTP status code
        http_response_code($status_code);

        // Output the response
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