
// Description: Java 25 in-memory RAM DbIO implementation for SecClusRoleMemb.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecClusRoleMembTable in-memory RAM DbIO implementation
 *	for SecClusRoleMemb.
 */
public class CFSecRamSecClusRoleMembTable
	implements ICFSecSecClusRoleMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecClusRoleMembPKey,
				CFSecBuffSecClusRoleMemb > dictByPKey
		= new HashMap< ICFSecSecClusRoleMembPKey,
				CFSecBuffSecClusRoleMemb >();
	private Map< CFSecBuffSecClusRoleMembByClusRoleIdxKey,
				Map< CFSecBuffSecClusRoleMembPKey,
					CFSecBuffSecClusRoleMemb >> dictByClusRoleIdx
		= new HashMap< CFSecBuffSecClusRoleMembByClusRoleIdxKey,
				Map< CFSecBuffSecClusRoleMembPKey,
					CFSecBuffSecClusRoleMemb >>();
	private Map< CFSecBuffSecClusRoleMembByLoginIdxKey,
				Map< CFSecBuffSecClusRoleMembPKey,
					CFSecBuffSecClusRoleMemb >> dictByLoginIdx
		= new HashMap< CFSecBuffSecClusRoleMembByLoginIdxKey,
				Map< CFSecBuffSecClusRoleMembPKey,
					CFSecBuffSecClusRoleMemb >>();

	public CFSecRamSecClusRoleMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecClusRoleMemb ensureRec(ICFSecSecClusRoleMemb rec) {
		return (((CFSecBuffSecClusRoleMembFactoryService)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb())).ensureRec(rec));
	}

	@Override
	public ICFSecSecClusRoleMemb createSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb iBuff )
	{
		final String S_ProcName = "createSecClusRoleMemb";
		
		CFSecBuffSecClusRoleMemb Buff = (CFSecBuffSecClusRoleMemb)ensureRec(iBuff);
		CFSecBuffSecClusRoleMembPKey pkey = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		pkey.setRequiredSecClusRoleId(Buff.getRequiredSecClusRoleId());
		pkey.setRequiredLoginId(Buff.getRequiredLoginId());
		pkey.setRequiredSecClusRoleId( Buff.getRequiredSecClusRoleId() );
		pkey.setRequiredLoginId( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerRole( pkey.getRequiredSecClusRoleId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		Buff.setRequiredSecClusRoleId( pkey.getRequiredSecClusRoleId() );
		Buff.setRequiredLoginId( pkey.getRequiredLoginId() );
		CFSecBuffSecClusRoleMembByClusRoleIdxKey keyClusRoleIdx = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();
		keyClusRoleIdx.setRequiredSecClusRoleId( Buff.getRequiredSecClusRoleId() );

		CFSecBuffSecClusRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecClusRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecClusRoleMembRole",
						"SecClusRoleMembRole",
						"SecClusRole",
						"SecClusRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictClusRoleIdx;
		if( dictByClusRoleIdx.containsKey( keyClusRoleIdx ) ) {
			subdictClusRoleIdx = dictByClusRoleIdx.get( keyClusRoleIdx );
		}
		else {
			subdictClusRoleIdx = new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByClusRoleIdx.put( keyClusRoleIdx, subdictClusRoleIdx );
		}
		subdictClusRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictLoginIdx;
		if( dictByLoginIdx.containsKey( keyLoginIdx ) ) {
			subdictLoginIdx = dictByLoginIdx.get( keyLoginIdx );
		}
		else {
			subdictLoginIdx = new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByLoginIdx.put( keyLoginIdx, subdictLoginIdx );
		}
		subdictLoginIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecClusRoleMemb.CLASS_CODE) {
				CFSecBuffSecClusRoleMemb retbuff = ((CFSecBuffSecClusRoleMemb)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusRoleMemb readDerived( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaAtomType$ LoginId )
	{
		{	$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ testSecClusRoleId = SecClusRoleId;
			if (testSecClusRoleId == null) {
				return( null );
			}
		}
		{	$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( SecClusRoleId );
		key.setRequiredLoginId( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecClusRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readDerived";
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( PKey.getRequiredSecClusRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecClusRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRoleMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.lockDerived";
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( PKey.getRequiredSecClusRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecClusRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRoleMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readAllDerived";
		ICFSecSecClusRoleMemb[] retList = new ICFSecSecClusRoleMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecClusRoleMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecClusRoleMemb[] readDerivedByClusRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readDerivedByClusRoleIdx";
		CFSecBuffSecClusRoleMembByClusRoleIdxKey key = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();

		key.setRequiredSecClusRoleId( SecClusRoleId );
		ICFSecSecClusRoleMemb[] recArray;
		if( dictByClusRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictClusRoleIdx
				= dictByClusRoleIdx.get( key );
			recArray = new ICFSecSecClusRoleMemb[ subdictClusRoleIdx.size() ];
			Iterator< CFSecBuffSecClusRoleMemb > iter = subdictClusRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictClusRoleIdx
				= new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByClusRoleIdx.put( key, subdictClusRoleIdx );
			recArray = new ICFSecSecClusRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusRoleMemb[] readDerivedByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readDerivedByLoginIdx";
		CFSecBuffSecClusRoleMembByLoginIdxKey key = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecClusRoleMemb[] recArray;
		if( dictByLoginIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictLoginIdx
				= dictByLoginIdx.get( key );
			recArray = new ICFSecSecClusRoleMemb[ subdictLoginIdx.size() ];
			Iterator< CFSecBuffSecClusRoleMemb > iter = subdictLoginIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdictLoginIdx
				= new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByLoginIdx.put( key, subdictLoginIdx );
			recArray = new ICFSecSecClusRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusRoleMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readDerivedByIdIdx() ";
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( SecClusRoleId );
		key.setRequiredLoginId( LoginId );
		ICFSecSecClusRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRoleMemb readRec( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaAtomType$ LoginId )
	{
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( SecClusRoleId );
		key.setRequiredLoginId( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecClusRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readRec";
		ICFSecSecClusRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRoleMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecClusRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRoleMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readAllRec";
		ICFSecSecClusRoleMemb buff;
		ArrayList<ICFSecSecClusRoleMemb> filteredList = new ArrayList<ICFSecSecClusRoleMemb>();
		ICFSecSecClusRoleMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRoleMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecClusRoleMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageAllRec( ICFSecAuthorization Authorization,
		$implIJavaOptAtomType$ priorSecClusRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusRoleMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readRecByIdIdx() ";
		ICFSecSecClusRoleMemb buff = readDerivedByIdIdx( Authorization,
			SecClusRoleId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
			return( (ICFSecSecClusRoleMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecClusRoleMemb[] readRecByClusRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readRecByClusRoleIdx() ";
		ICFSecSecClusRoleMemb buff;
		ArrayList<ICFSecSecClusRoleMemb> filteredList = new ArrayList<ICFSecSecClusRoleMemb>();
		ICFSecSecClusRoleMemb[] buffList = readDerivedByClusRoleIdx( Authorization,
			SecClusRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRoleMemb[0] ) );
	}

	@Override
	public ICFSecSecClusRoleMemb[] readRecByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMemb.readRecByLoginIdx() ";
		ICFSecSecClusRoleMemb buff;
		ArrayList<ICFSecSecClusRoleMemb> filteredList = new ArrayList<ICFSecSecClusRoleMemb>();
		ICFSecSecClusRoleMemb[] buffList = readDerivedByLoginIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRoleMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecClusRoleMemb buffer instances identified by the duplicate key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageRecByClusRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaOptAtomType$ priorSecClusRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageRecByClusRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecClusRoleMemb buffer instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageRecByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId,
		$implIJavaOptAtomType$ priorSecClusRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageRecByLoginIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusRoleMemb updateSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb iBuff )
	{
		CFSecBuffSecClusRoleMemb Buff = (CFSecBuffSecClusRoleMemb)ensureRec(iBuff);
		CFSecBuffSecClusRoleMembPKey pkey = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		pkey = (CFSecBuffSecClusRoleMembPKey)Buff.getPKey();
		CFSecBuffSecClusRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecClusRoleMemb",
				"Existing record not found",
				"Existing record not found",
				"SecClusRoleMemb",
				"SecClusRoleMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecClusRoleMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecClusRoleMembByClusRoleIdxKey existingKeyClusRoleIdx = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();
		existingKeyClusRoleIdx.setRequiredSecClusRoleId( existing.getRequiredSecClusRoleId() );

		CFSecBuffSecClusRoleMembByClusRoleIdxKey newKeyClusRoleIdx = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();
		newKeyClusRoleIdx.setRequiredSecClusRoleId( Buff.getRequiredSecClusRoleId() );

		CFSecBuffSecClusRoleMembByLoginIdxKey existingKeyLoginIdx = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();
		existingKeyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecClusRoleMembByLoginIdxKey newKeyLoginIdx = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();
		newKeyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecClusRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecClusRoleMemb",
						"Container",
						"Container",
						"SecClusRoleMembRole",
						"SecClusRoleMembRole",
						"SecClusRole",
						"SecClusRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusRoleIdx.get( existingKeyClusRoleIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusRoleIdx.containsKey( newKeyClusRoleIdx ) ) {
			subdict = dictByClusRoleIdx.get( newKeyClusRoleIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByClusRoleIdx.put( newKeyClusRoleIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByLoginIdx.get( existingKeyLoginIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByLoginIdx.containsKey( newKeyLoginIdx ) ) {
			subdict = dictByLoginIdx.get( newKeyLoginIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb >();
			dictByLoginIdx.put( newKeyLoginIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecClusRoleMembTable.deleteSecClusRoleMemb() ";
		CFSecBuffSecClusRoleMemb Buff = (CFSecBuffSecClusRoleMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecClusRoleMembPKey pkey = (CFSecBuffSecClusRoleMembPKey)(Buff.getPKey());
		CFSecBuffSecClusRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecClusRoleMemb",
				pkey );
		}
		CFSecBuffSecClusRoleMembByClusRoleIdxKey keyClusRoleIdx = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();
		keyClusRoleIdx.setRequiredSecClusRoleId( existing.getRequiredSecClusRoleId() );

		CFSecBuffSecClusRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecClusRoleMembPKey, CFSecBuffSecClusRoleMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusRoleIdx.get( keyClusRoleIdx );
		subdict.remove( pkey );

		subdict = dictByLoginIdx.get( keyLoginIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecClusRoleMembByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecClusRoleId,
		$implIJavaAtomType$ LoginId )
	{
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( SecClusRoleId );
		key.setRequiredLoginId( LoginId );
		deleteSecClusRoleMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		CFSecBuffSecClusRoleMembPKey key = (CFSecBuffSecClusRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newPKey());
		key.setRequiredSecClusRoleId( PKey.getRequiredSecClusRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		CFSecBuffSecClusRoleMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecClusRoleMemb cur;
		LinkedList<CFSecBuffSecClusRoleMemb> matchSet = new LinkedList<CFSecBuffSecClusRoleMemb>();
		Iterator<CFSecBuffSecClusRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRoleMemb)(schema.getTableSecClusRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecClusRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusRoleMembByClusRoleIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argSecClusRoleId )
	{
		CFSecBuffSecClusRoleMembByClusRoleIdxKey key = (CFSecBuffSecClusRoleMembByClusRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByClusRoleIdxKey();
		key.setRequiredSecClusRoleId( argSecClusRoleId );
		deleteSecClusRoleMembByClusRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleMembByClusRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembByClusRoleIdxKey argKey )
	{
		CFSecBuffSecClusRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusRoleMemb> matchSet = new LinkedList<CFSecBuffSecClusRoleMemb>();
		Iterator<CFSecBuffSecClusRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRoleMemb)(schema.getTableSecClusRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecClusRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argLoginId )
	{
		CFSecBuffSecClusRoleMembByLoginIdxKey key = (CFSecBuffSecClusRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRoleMemb().newByLoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecClusRoleMembByLoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembByLoginIdxKey argKey )
	{
		CFSecBuffSecClusRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusRoleMemb> matchSet = new LinkedList<CFSecBuffSecClusRoleMemb>();
		Iterator<CFSecBuffSecClusRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRoleMemb)(schema.getTableSecClusRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecClusRoleMemb( Authorization, cur );
		}
	}
}
