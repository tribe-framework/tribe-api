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

        $this->url_parts = explode('/', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        $this->type = (string) ($this->url_parts[2] ?? '');
        $this->id = (int) ($this->url_parts[3] ?? 0);

    }

    public function jsonAPI($version = '1.1') {

        if ($version == '1.1') {

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
                $object = array_merge($this->core->getObject($object['data']['id']), $object['data'], $object['data']['attributes']['modules']);
                unset($object['attributes']);
                
                $object = $this->core->getObject($this->core->pushObject($object));

                $document = new ResourceDocument($this->type, $object['id']);
                $document->add('modules', $object);
                $document->add('slug', $object['slug']);
                $document->sendResponse();
            }

            else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $object = $this->requestBody;
                $object = array_merge($object['data'], $object['data']['attributes']['modules']);
                unset($object['attributes']);

                if ($object['type'] == 'user')
                    $object['user_id'] = $this->auth->getUniqueUserID();

                $object = $this->core->getObject($this->core->pushObject($object));

                $document = new ResourceDocument($this->type, $object['id']);
                $document->add('modules', $object);
                $document->add('slug', $object['slug']);
                $document->sendResponse();
            }

            else {

                if ($this->type == 'webapp') {
                    $object = $this->config->getTypes();

                    if ( ($_GET['include'] ?? false) && in_array('total_objects', $_GET['include']) ) {
                        foreach ($object as $key => $value) {
                            $object[$key]['total_objects'] = $this->core->getTypeObjectsCount($key);
                        }
                    }

                    $document = new ResourceDocument($this->type, 0);
                    $document->add('modules', $object);
                    $document->add('slug', ($object['slug'] ?? 'webapp'));
                    $document->sendResponse();
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
                            $show_partial_search_results = (($_GET['filter'] ?? false) ? boolval(true) : boolval(false))
                        ))
                    {
                        $objectr = $this->core->getObjects($this->ids);
                        $objects = [];
                        
                        //to sort accurately
                        foreach ($this->ids as $this->idr) {
                            $objects[] = $objectr[$this->idr['id']];
                        }

                        $i = 0;
                        foreach ($objects as $object) {
                            $documents[$i] = new ResourceDocument($this->type, $object['id']);
                            $documents[$i]->add('modules', $object);
                            $documents[$i]->add('slug', $object['slug']);
                            $i++;
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
                            $show_partial_search_results = ($_GET['filter'] ? boolval(true) : boolval(false))
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

    /**
     * allow access to api only if the request meets certain permissions
     * this function fetches bearer_token from auth header and verifies the
     * jwt. Request only goes through if "allowed_role" matches the role
     * on token.
     */
    public function auth($allowed_role): array
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
